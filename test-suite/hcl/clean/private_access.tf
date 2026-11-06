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
