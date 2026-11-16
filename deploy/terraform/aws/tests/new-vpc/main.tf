# Test fixture: the module next to subnets and route tables that it is created
# with, whose IDs are unknown until apply.

resource "aws_vpc" "this" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  for_each = { "us-east-1a" = "10.0.0.0/24", "us-east-1b" = "10.0.1.0/24" }

  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = each.value
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.public

  vpc_id = aws_vpc.this.id
}

module "natterjack" {
  source = "../.."

  cluster_name              = "prod-east"
  slot_subnets              = { for z, s in aws_subnet.public : z => s.id }
  bootstrap_route_table_ids = { for z, r in aws_route_table.private : z => r.id }
}
