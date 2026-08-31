package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3Options configures the object-store archive. The defaults target Cloudflare
// R2; the same client speaks to S3, MinIO or anything else with an S3 API.
type S3Options struct {
	Bucket string

	// Endpoint is the S3 API endpoint. For R2 this is
	// https://<account-id>.r2.cloudflarestorage.com. Empty means real AWS S3.
	Endpoint string

	// Region. R2 ignores it but the signing process does not, so it must be
	// set to something; "auto" is R2's convention.
	Region string

	// Credentials. When both are empty the AWS default chain is used, which
	// picks up environment variables, an instance role, or SSO.
	AccessKeyID     string
	SecretAccessKey string

	// UsePathStyle addresses buckets as endpoint/bucket/key rather than
	// bucket.endpoint/key. Needed by MinIO and most self-hosted gateways.
	UsePathStyle bool
}

// S3 is an [Archiver] backed by an S3-compatible object store.
type S3 struct {
	client *s3.Client
	bucket string
	seen   *seenCache
}

// NewS3 builds an object-store archive.
func NewS3(ctx context.Context, opts S3Options) (*S3, error) {
	if opts.Bucket == "" {
		return nil, errors.New("archive: bucket is required")
	}
	if opts.Region == "" {
		opts.Region = "auto"
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(opts.Region),

		// Newer SDK releases add a CRC checksum to every request by default.
		// Several S3-compatible gateways, R2 included, have rejected or
		// mishandled those, and the failure surfaces as an opaque 400 a long
		// way from its cause. Only send a checksum where the operation
		// genuinely requires one.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	}
	if opts.AccessKeyID != "" || opts.SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKeyID, opts.SecretAccessKey, "")))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("archive: load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)
		}
		o.UsePathStyle = opts.UsePathStyle
	})

	return &S3{client: client, bucket: opts.Bucket, seen: newSeenCache(8192)}, nil
}

// Name implements [Archiver].
func (a *S3) Name() string { return "s3://" + a.bucket }

// Put stores data under its content hash.
//
// Because the key is the hash, a repeat delivery of unchanged bytes is already
// present, so the object is checked for before it is uploaded. That trade is
// worth making: a HEAD is a few hundred bytes, and a daily blocklist that has
// not changed is megabytes.
func (a *S3) Put(ctx context.Context, data []byte, mediaType string) (string, error) {
	hash := Hash(data)
	key, err := Key(hash)
	if err != nil {
		return "", err
	}
	ref := "s3://" + a.bucket + "/" + key

	if a.seen.has(key) {
		return ref, nil
	}
	exists, err := a.exists(ctx, key)
	if err != nil {
		return "", err
	}
	if exists {
		a.seen.add(key)
		return ref, nil
	}

	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	_, err = a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mediaType),
		Metadata:    map[string]string{"content-sha256": strings.TrimPrefix(hash, HashPrefix)},
	})
	if err != nil {
		return "", fmt.Errorf("archive: put %s: %w", ref, err)
	}
	a.seen.add(key)
	return ref, nil
}

// Get retrieves a payload by the reference [S3.Put] returned.
func (a *S3) Get(ctx context.Context, ref string) ([]byte, error) {
	key, err := a.keyFromRef(ref)
	if err != nil {
		return nil, err
	}
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, ref)
		}
		return nil, fmt.Errorf("archive: get %s: %w", ref, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("archive: read %s: %w", ref, err)
	}
	return data, nil
}

func (a *S3) exists(ctx context.Context, key string) (bool, error) {
	_, err := a.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("archive: head %s: %w", key, err)
}

// keyFromRef accepts both the s3://bucket/key form this package writes and a
// bare key, so references written by a collector using its own conventions
// still resolve.
func (a *S3) keyFromRef(ref string) (string, error) {
	if !strings.HasPrefix(ref, "s3://") {
		if ref == "" {
			return "", errors.New("archive: empty reference")
		}
		return strings.TrimPrefix(ref, "/"), nil
	}
	rest := strings.TrimPrefix(ref, "s3://")
	bucket, key, ok := strings.Cut(rest, "/")
	if !ok || key == "" {
		return "", fmt.Errorf("archive: reference %q has no object key", ref)
	}
	if bucket != a.bucket {
		return "", fmt.Errorf("archive: reference %q is in bucket %q, this archive is %q",
			ref, bucket, a.bucket)
	}
	return key, nil
}

// isNotFound covers the several ways an S3-compatible store can say "no".
// HeadObject in particular returns a bare 404 with no error code, because the
// HEAD response has no body to put one in.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	var respErr interface{ HTTPStatusCode() int }
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	return false
}
