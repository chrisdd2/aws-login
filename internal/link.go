package internal

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	linkVersion     = 1
	linkFlagDeflate = 0x80
	linkMacSize     = 16
	linkMaxUrlSize  = 8192
	linkMacDomain   = "aws-login-link"
)

var linkDict = []byte("" +
	"ap-southeast-2ap-southeast-1ap-northeast-1ap-south-1ca-central-1sa-east-1" +
	"eu-north-1eu-central-1eu-west-3eu-west-2us-west-2us-west-1us-east-2us-east-1eu-west-1" +
	"&showversions=false&prefix=&bucketType=general&tab=objects&tab=properties&tab=permissions" +
	"/cloudwatch/home?region=/lambda/home?region=/ec2/home?region=/iam/home#/roles/details/" +
	"/dynamodbv2/home?region=/rds/home?region=/sqs/v3/home?region=/glue/home?region=" +
	".console.aws.amazon.com/https://console.aws.amazon.com/" +
	"?region=https://s3.console.aws.amazon.com/s3/buckets/")

var (
	ErrLinkMalformed = errors.New("malformed link token")
	ErrLinkSignature = errors.New("invalid link signature")
)

type LinkClaims struct {
	Account string
	Role    string
	Url     string
}

func linkMac(key []byte, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(linkMacDomain))
	m.Write(payload)
	return m.Sum(nil)[:linkMacSize]
}

func deflateUrl(u string) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriterDict(&buf, flate.BestCompression, linkDict)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(u)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func SignLinkToken(key []byte, account string, role string, url string) (string, error) {
	if len(account) != 12 {
		return "", WrapError(fmt.Errorf("account id %q must be 12 digits", account), "SignLinkToken")
	}
	accountNum, err := strconv.ParseUint(account, 10, 64)
	if err != nil {
		return "", WrapError(err, "SignLinkToken")
	}
	if len(url) > linkMaxUrlSize {
		return "", WrapError(errors.New("url too long"), "SignLinkToken")
	}

	header := byte(linkVersion)
	urlBytes := []byte(url)
	if compressed, err := deflateUrl(url); err == nil && len(compressed) < len(urlBytes) {
		header |= linkFlagDeflate
		urlBytes = compressed
	}

	payload := []byte{header}
	payload = binary.AppendUvarint(payload, accountNum)
	payload = binary.AppendUvarint(payload, uint64(len(role)))
	payload = append(payload, role...)
	payload = append(payload, urlBytes...)
	payload = append(payload, linkMac(key, payload)...)

	Debugf("SignLinkToken: issuing link for %s/%s to %s", account, role, url)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func ParseLinkToken(key []byte, tokenStr string) (*LinkClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil || len(raw) < 1+linkMacSize {
		return nil, ErrLinkMalformed
	}
	payload, mac := raw[:len(raw)-linkMacSize], raw[len(raw)-linkMacSize:]
	if !hmac.Equal(mac, linkMac(key, payload)) {
		return nil, ErrLinkSignature
	}

	header := payload[0]
	if header&^linkFlagDeflate != linkVersion {
		return nil, ErrLinkMalformed
	}
	rest := payload[1:]
	accountNum, n := binary.Uvarint(rest)
	if n <= 0 || accountNum > 999999999999 {
		return nil, ErrLinkMalformed
	}
	rest = rest[n:]
	roleLen, n := binary.Uvarint(rest)
	if n <= 0 || roleLen > uint64(len(rest)-n) {
		return nil, ErrLinkMalformed
	}
	rest = rest[n:]
	role, urlBytes := string(rest[:roleLen]), rest[roleLen:]

	if header&linkFlagDeflate != 0 {
		r := flate.NewReaderDict(bytes.NewReader(urlBytes), linkDict)
		defer r.Close()
		urlBytes, err = io.ReadAll(io.LimitReader(r, linkMaxUrlSize+1))
		if err != nil || len(urlBytes) > linkMaxUrlSize {
			return nil, ErrLinkMalformed
		}
	}

	claims := &LinkClaims{
		Account: fmt.Sprintf("%012d", accountNum),
		Role:    role,
		Url:     string(urlBytes),
	}
	Debugf("ParseLinkToken: link for %s/%s to %s", claims.Account, claims.Role, claims.Url)
	return claims, nil
}
