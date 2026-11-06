resource "aws_security_group" "administration" {
  name = "private-administration"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.10.0.0/16"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "example-ubs-private-reports"
  acl    = "private"
}

provider "aws" {
  region   = "us-east-1"
  insecure = false
}

resource "aws_iam_policy" "report_reader" {
  name = "example-report-reader-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::example-ubs-private-reports/*"
    }]
  })
}
