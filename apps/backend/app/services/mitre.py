MITRE_MAPPINGS = {
    "failed_login_burst": ("T1110", "Brute Force"),
    "impossible_travel": ("T1078", "Valid Accounts"),
    "privilege_escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "beaconing": ("T1071", "Application Layer Protocol"),
    "ml_anomaly": ("T1036", "Masquerading"),
}


def technique_for(category: str) -> tuple[str, str]:
    return MITRE_MAPPINGS.get(category, ("T1087", "Account Discovery"))

