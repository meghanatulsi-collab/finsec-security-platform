import boto3
import json
from datetime import datetime
from collections import defaultdict


# These are the dangerous ports your tool checks
# Dictionary: port number → info about it
DANGEROUS_PORTS = {
    22:   {"name": "SSH",        "risk": "HIGH"},
    3306: {"name": "MySQL",      "risk": "HIGH"},
    5432: {"name": "PostgreSQL", "risk": "HIGH"},
    3389: {"name": "RDP",        "risk": "HIGH"},
    27017:{"name": "MongoDB",    "risk": "HIGH"},
    6379: {"name": "Redis",      "risk": "HIGH"},
    21:   {"name": "FTP",        "risk": "HIGH"},
    80:   {"name": "HTTP",       "risk": "MEDIUM"},
    8080: {"name": "HTTP-Alt",   "risk": "MEDIUM"},
}

# This means open to entire internet
OPEN_TO_WORLD = ["0.0.0.0/0", "::/0"]



def check_security_group(sg):
    
    findings = []
    
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", "unnamed")
    
    for rule in sg["IpPermissions"]:
        
        from_port = rule.get("FromPort", 0)
        protocol  = rule.get("IpProtocol", "tcp")
        
        all_ranges = (
            [r["CidrIp"]   for r in rule.get("IpRanges", [])] +
            [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
        )
        
        for cidr in all_ranges:
            
            if cidr in OPEN_TO_WORLD:
                
                if protocol == "-1":
                    findings.append({
                        "risk":   "HIGH",
                        "port":   "ALL",
                        "reason": "All traffic open to entire internet"
                    })
                
                elif from_port in DANGEROUS_PORTS:
                    info = DANGEROUS_PORTS[from_port]
                    findings.append({
                        "risk":   info["risk"],
                        "port":   f"{from_port} ({info['name']})",
                        "reason": f"Port {from_port} open to entire internet"
                    })
    
    return findings


def run_audit():

    print("=" * 50)
    print("  FINSEC — AWS SECURITY AUDIT")
    print("=" * 50)
    print("\nConnecting to AWS...")

    # Connect to AWS EC2
    ec2 = boto3.client("ec2")
    print(ec2,"ec222222")

    print("Fetching all security groups...")

    # Get ALL security groups from your AWS account
    response = ec2.describe_security_groups()
    print(response,"Responseeeeeeeee")
    security_groups = response["SecurityGroups"]

    # print(f"Found {len(security_groups)} security groups\n")
    print("Number of security groups ",len(security_groups))
    print("-" * 50)

    # Store all results
    all_results = []

    # Loop through every security group
    for sg in security_groups:

        sg_id   = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")

        # Call the function you already wrote
        findings = check_security_group(sg)
        print(findings,"2222222222")

        # Risk level
        if findings:
            overall_risk = "HIGH"
            print(f"  ⚠️  {sg_name} ({sg_id}) — HIGH RISK")
        else:
            overall_risk = "CLEAN"
            print(f"  ✅ {sg_name} ({sg_id}) — CLEAN")

        # Save result
        all_results.append({
            "sg_id":        sg_id,
            "sg_name":      sg_name,
            "findings":     findings,
            "overall_risk": overall_risk
        })

    # Print detailed findings
    print("\n" + "=" * 50)
    print("  DETAILED FINDINGS")
    print("=" * 50)

    for result in all_results:
        if result["findings"]:
            print(f"\n  ⚠️  {result['sg_name']} ({result['sg_id']})")
            for f in result["findings"]:
                print(f"     → {f['risk']} RISK | Port {f['port']}")
                print(f"       Reason: {f['reason']}")

    # Print summary
    high_count  = sum(1 for r in all_results if r["overall_risk"] == "HIGH")
    clean_count = sum(1 for r in all_results if r["overall_risk"] == "CLEAN")
    total       = len(all_results)

    print("\n" + "=" * 50)
    print("  AUDIT SUMMARY")
    print("=" * 50)
    print(f"  Total scanned : {total}")
    print(f"  HIGH risk     : {high_count} ⚠️")
    print(f"  Clean         : {clean_count} ✅")
    print("=" * 50)

    # Save results to JSON file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"audit_report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n  Report saved to: {filename}")
    print("=" * 50)


# This starts the program when you run the file
if __name__ == "__main__":
    run_audit()

    