locals {
 name_prefix = "asyraf"
}

data "aws_vpc" "selected" {
  filter {
    name   = "tag:Name"
    values = ["shared-vpc"]
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
  filter {
    name   = "tag:Name"
    values = ["*public*"]
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
  filter {
    name   = "tag:Name"
    values = ["*private*"]
  }
}

resource "aws_dynamodb_table" "books_table" {
  name           = "${local.name_prefix}-bookinventory-assignment"  # Replace with your table name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key = "ISBN"
  range_key = "Genre"

  attribute {
    name = "ISBN"
    type = "S"
  }

  attribute {
    name = "Genre"
    type = "S"
  }
}

resource "aws_iam_role" "role_db" {
  name = "${local.name_prefix}-role-dynamodb"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "policy_db" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:ListTables"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.books_table.arn]
  }
}

resource "aws_iam_policy" "policy_db" {
 name = "${local.name_prefix}-policy-example"
 ## Option 1: Attach data block policy document
 policy = data.aws_iam_policy_document.policy_db.json
}

resource "aws_iam_role_policy_attachment" "attach_db" {
 role       = aws_iam_role.role_db.name
 policy_arn = aws_iam_policy.policy_db.arn
}

resource "aws_iam_instance_profile" "profile_db" {
 name = "${local.name_prefix}-profile-example"
 role = aws_iam_role.role_db
}

resource "aws_instance" "dynamodb_reader" {
  ami                         = "ami-04c913012f8977029"
  instance_type               = "t2.micro"
  subnet_id                   = data.aws_subnets.public.ids[0]  #Public Subnet ID, e.g. subnet-xxxxxxxxxxx
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.dynamodb_reader.id]
 
  iam_instance_profile = aws_iam_instance_profile.profile_db.id

  tags = {
    Name = "${local.name_prefix}-ec2"
  }
}

resource "aws_security_group" "dynamodb_reader" {
  name        = "${local.name_prefix}-sg" #Security group name, e.g. jazeel-terraform-security-group
  description = "Allow SSH inbound"
  vpc_id      = data.aws_vpc.selected.id 
  lifecycle {
    create_before_destroy = true
  } #VPC ID (Same VPC as your EC2 subnet above), E.g. vpc-xxxxxxx
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_ipv4" {
  security_group_id = aws_security_group.dynamodb_reader.id
  cidr_ipv4         = "0.0.0.0/0"  
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}

resource "aws_vpc_security_group_egress_rule" "allow_https_traffic_ipv4" {
  security_group_id = aws_security_group.dynamodb_reader.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "allow_https_traffic_ipv6" {
  security_group_id = aws_security_group.dynamodb_reader.id
  cidr_ipv6         = "::/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}



