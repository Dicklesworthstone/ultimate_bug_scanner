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
