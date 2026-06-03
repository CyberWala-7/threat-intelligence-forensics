import asyncio
from src.threat_intel import ThreatIntel
from src.malware_detector import MalwareDetector
from src.credential_detector import CredentialDetector

async def test_malicious_ip():
    ti = ThreatIntel()
    # Known malicious IP from AbuseIPDB (replace with a real one)
    result = await ti.check_ip("64.176.194.36")
    print("IP check:", result)
    await ti.close()

async def test_malicious_hash():
    md = MalwareDetector()
    # EICAR test hash
    result = await md.check_hash("44d88612fea8a8f36de82e1278abb02f")
    print("Hash check:", result.model_dump(mode='json'))
    await md.close()

async def test_breached_email():
    cd = CredentialDetector()
    # Replace with a real breached email if you have HIBP paid key
    result = await cd.check_credential("test@test")
    print("Email check:", result.model_dump(mode='json'))

async def main():
    await test_malicious_ip()
    await test_malicious_hash()
    await test_breached_email()

if __name__ == "__main__":
    asyncio.run(main())
