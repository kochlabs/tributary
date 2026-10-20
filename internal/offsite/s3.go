package offsite

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/kochlabs/tributary/internal/config"
)

// s3Target writes objects under a key prefix in an S3 or S3-compatible
// bucket (AWS, MinIO, Wasabi, Backblaze B2, Cloudflare R2, Ceph, …). An
// object only becomes visible once its upload completes.
type s3Target struct {
	c      *minio.Client
	bucket string
	prefix string // "" or "folder/"
}

func openS3(ctx context.Context, d config.BackupDestination, env Env) (Target, error) {
	host, secure := "s3.amazonaws.com", true
	if d.Endpoint != "" {
		u, err := url.Parse(d.Endpoint)
		if err != nil {
			return nil, err
		}
		host, secure = u.Host, u.Scheme == "https"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: env.RootCAs, MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = 60 * time.Second
	lookup := minio.BucketLookupAuto
	if d.PathStyle {
		lookup = minio.BucketLookupPath
	}
	c, err := minio.New(host, &minio.Options{Creds: credentials.NewStaticV4(d.AccessKey, d.SecretKey, ""), Secure: secure,
		Region: d.Region, BucketLookup: lookup, Transport: tr})
	if err != nil {
		return nil, err
	}
	prefix := d.Path
	if prefix != "" {
		prefix += "/"
	}
	t := &s3Target{c: c, bucket: d.Bucket, prefix: prefix}
	// Fail early, with the provider's explanation, on credentials or a
	// missing bucket.
	if err := t.check(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *s3Target) check(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx) // stops the listing after one object
	defer cancel()
	for o := range t.c.ListObjects(ctx, t.bucket, minio.ListObjectsOptions{Prefix: t.prefix, MaxKeys: 1}) {
		if o.Err != nil {
			return explainS3(o.Err)
		}
		break
	}
	return nil
}

func explainS3(err error) error {
	if err == nil {
		return nil
	}
	r := minio.ToErrorResponse(err)
	switch r.Code {
	case "NoSuchBucket":
		return errors.New("the bucket doesn't exist")
	case "InvalidAccessKeyId":
		return errors.New("the access key was rejected")
	case "SignatureDoesNotMatch":
		return errors.New("the secret key was rejected")
	case "AccessDenied":
		return errors.New("access denied (check the key's permissions on the bucket)")
	}
	return err
}

func (t *s3Target) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	_, err := t.c.PutObject(ctx, t.bucket, t.prefix+name, r, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return explainS3(err)
	}
	return nil
}

func (t *s3Target) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	o, err := t.c.GetObject(ctx, t.bucket, t.prefix+name, minio.GetObjectOptions{})
	if err != nil {
		return nil, explainS3(err)
	}
	return o, nil
}

func (t *s3Target) List(ctx context.Context) ([]Object, error) {
	var out []Object
	for o := range t.c.ListObjects(ctx, t.bucket, minio.ListObjectsOptions{Prefix: t.prefix}) {
		if o.Err != nil {
			return nil, explainS3(o.Err)
		}
		name := strings.TrimPrefix(o.Key, t.prefix)
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		out = append(out, Object{Name: name, Size: o.Size, Modified: o.LastModified})
	}
	return out, nil
}

func (t *s3Target) Delete(ctx context.Context, name string) error {
	return explainS3(t.c.RemoveObject(ctx, t.bucket, t.prefix+name, minio.RemoveObjectOptions{}))
}

func (t *s3Target) Close() error { return nil }
