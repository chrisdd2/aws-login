package aws_test

import (
	"testing"

	"github.com/chrisdd2/aws-login/aws"
	"github.com/stretchr/testify/assert"
)

func TestPrincipal(t *testing.T) {
	roleArn := "arn:aws:sts::123456789012:assumed-role/SomeRole/i-0abcdef1234567890"
	userArn := "arn:aws:iam::123456789012:user/your-username"
	roleRes := aws.PrincipalFromSts(roleArn)
	userRes := aws.PrincipalFromSts(userArn)
	assert.Equal(t, "arn:aws:iam::123456789012:role/SomeRole", roleRes)
	assert.Equal(t, userArn, userRes)
}
