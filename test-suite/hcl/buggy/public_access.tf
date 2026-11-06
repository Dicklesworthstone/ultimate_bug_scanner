resource "aws_security_group" "administration" {
  name = "public-administration"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "example-ubs-public-reports"
  acl    = "public-read"
}

provider "aws" {
  region   = "us-east-1"
  insecure = true
}

resource "aws_iam_policy" "administrator" {
  name = "example-unrestricted-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
