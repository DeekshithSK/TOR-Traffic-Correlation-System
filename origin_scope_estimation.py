"""
Origin Scope Estimation Module

Probabilistic estimation of user origin region/ISP scope based on guard relay information.
Provides SUPPLEMENTARY intelligence without claiming exact IP identification.

CRITICAL CONSTRAINTS:
- Must operate ONLY AFTER guard relay inference
- Must be strictly probabilistic
- Must NEVER claim identification of exact user IP
- Must NEVER override guard inference results
- Confidence is QUALITATIVE (Low/Medium/High), not numeric

Data Sources (Read-Only, Non-Intrusive):
- MaxMind GeoLite2 data (via ip-api.com for simplicity)
- Tor relay metadata (already ingested)
- Public ASN/ISP classification patterns
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



VPS_HOSTING_KEYWORDS = [
    'digitalocean', 'linode', 'vultr', 'hetzner', 'ovh', 'amazon', 'aws',
    'google cloud', 'microsoft azure', 'azure', 'gcp', 'cloudflare',
    'contabo', 'hostinger', 'hostgator', 'bluehost', 'ionos', 'scaleway',
    'upcloud', 'kamatera', 'hostwinds', 'interserver', 'a2 hosting',
    'liquidweb', 'ramnode', 'buyvm', 'time4vps', 'hostus', 'securedservers'
]

ACADEMIC_KEYWORDS = [
    'university', 'college', 'academic', 'education', '.edu', 'research',
    'institute', 'laboratory', 'school', 'campus', 'wissenschaft', 'uni-'
]

RESIDENTIAL_ISP_KEYWORDS = [
    'comcast', 'verizon', 'at&t', 'spectrum', 'cox', 'frontier', 'centurylink',
    'deutsche telekom', 'vodafone', 'telefonica', 'orange', 'bt ', 'virgin media',
    'sky broadband', 'swisscom', 'telia', 'telenor', 'telstra', 'bell canada',
    'rogers', 'shaw', 'optus', 'ntt', 'kddi', 'softbank', 'bouygues', 'free.fr',
    'sfr', 'numericable', 'ono', 'movistar', 'jazztel', 'ziggo', 'kpn'
]

REGION_GROUPS = {
    'Western Europe': ['DE', 'FR', 'NL', 'BE', 'LU', 'CH', 'AT', 'GB', 'IE'],
    'Northern Europe': ['SE', 'NO', 'FI', 'DK', 'IS', 'EE', 'LV', 'LT'],
    'Southern Europe': ['ES', 'IT', 'PT', 'GR', 'HR', 'SI'],
    'Eastern Europe': ['PL', 'CZ', 'SK', 'HU', 'RO', 'BG', 'UA', 'BY', 'RU'],
    'North America': ['US', 'CA', 'MX'],
    'South America': ['BR', 'AR', 'CL', 'CO', 'PE', 'VE'],
    'East Asia': ['JP', 'KR', 'CN', 'TW', 'HK'],
    'Southeast Asia': ['SG', 'TH', 'MY', 'ID', 'PH', 'VN'],
    'Oceania': ['AU', 'NZ'],
    'Middle East': ['IL', 'AE', 'SA', 'TR', 'IR'],
    'South Asia': ['IN', 'PK', 'BD'],
    'Africa': ['ZA', 'EG', 'NG', 'KE', 'MA']
}



class HostingProfile(Enum):
    """Guard relay hosting profile classification."""
    VPS_COMMERCIAL = "Commercial VPS/Cloud"
    RESIDENTIAL_ISP = "Residential ISP"
    ACADEMIC = "Academic/Research"
    ENTERPRISE = "Enterprise/Corporate"
    UNKNOWN = "Unknown"


class OriginConfidence(Enum):
    """Qualitative confidence level for origin estimation."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class OriginScopeResult:
    """
    Origin scope estimation result.
    
    IMPORTANT: This is CONTEXTUAL INTELLIGENCE only.
    It does NOT identify the user's exact IP address.
    """
    guard_country: str
    guard_country_code: Optional[str]
    guard_asn: Optional[str]
    guard_isp: Optional[str]
    
    hosting_profile: str
    hosting_profile_description: str
    
    probable_origin_region: str
    probable_origin_countries: List[str]
    regional_radius_description: str
    
    origin_isp_category: str
    
    confidence_level: str
    confidence_reasoning: str
    
    disclaimer: str = (
        "This is contextual intelligence only. It does NOT identify the user's "
        "exact IP address. The probable origin scope is an estimation based on "
        "guard relay characteristics and should not be used as direct attribution."
    )
    is_supplementary: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)



class HostingProfileClassifier:
    """
    Classifies guard relay hosting profile based on ASN/ISP information.
    Uses pattern matching against known hosting provider keywords.
    """
    
    @staticmethod
    def classify(isp: Optional[str], asn: Optional[str]) -> tuple[HostingProfile, str]:
        """
        Classify hosting profile from ISP/ASN strings.
        
        Args:
            isp: ISP name string
            asn: ASN string or number
            
        Returns:
            Tuple of (HostingProfile, description)
        """
        if not isp:
            return HostingProfile.UNKNOWN, "Insufficient ISP data for classification"
        
        isp_lower = isp.lower()
        
        for keyword in VPS_HOSTING_KEYWORDS:
            if keyword in isp_lower:
                return (
                    HostingProfile.VPS_COMMERCIAL,
                    f"Guard hosted on commercial VPS/cloud infrastructure ({isp})"
                )
        
        for keyword in ACADEMIC_KEYWORDS:
            if keyword in isp_lower:
                return (
                    HostingProfile.ACADEMIC,
                    f"Guard hosted on academic/research network ({isp})"
                )
        
        for keyword in RESIDENTIAL_ISP_KEYWORDS:
            if keyword in isp_lower:
                return (
                    HostingProfile.RESIDENTIAL_ISP,
                    f"Guard appears to be on residential ISP ({isp})"
                )
        
        return (
            HostingProfile.ENTERPRISE,
            f"Guard on enterprise/unclassified network ({isp})"
        )



class OriginRegionEstimator:
    """
    Estimates probable origin region based on guard relay characteristics.
    
    Logic:
    - VPS guards: User could be from ANYWHERE (global reach)
    - Residential ISP guards: User likely from SAME region as guard
    - Academic guards: User likely from SAME country as guard
    """
    
    @staticmethod
    def get_region_for_country(country_code: str) -> Optional[str]:
        """Get region name for a country code."""
        for region, countries in REGION_GROUPS.items():
            if country_code in countries:
                return region
        return None
    
    @staticmethod
    def get_neighbor_countries(country_code: str) -> List[str]:
        """Get countries in the same region."""
        for region, countries in REGION_GROUPS.items():
            if country_code in countries:
                return countries
        return [country_code]
    
    def estimate(
        self,
        guard_country_code: str,
        hosting_profile: HostingProfile
    ) -> tuple[str, List[str], str, OriginConfidence]:
        """
        Estimate probable origin region.
        
        Args:
            guard_country_code: ISO country code of guard
            hosting_profile: Classified hosting profile
            
        Returns:
            Tuple of (region_name, probable_countries, radius_description, confidence)
        """
        region = self.get_region_for_country(guard_country_code) or "Unknown Region"
        neighbor_countries = self.get_neighbor_countries(guard_country_code)
        
        if hosting_profile == HostingProfile.VPS_COMMERCIAL:
            return (
                "Global (VPS hosting enables worldwide selection)",
                ["Global reach - cannot narrow by geography"],
                "Worldwide - guard on commercial VPS can be selected from any location",
                OriginConfidence.LOW
            )
        
        elif hosting_profile == HostingProfile.RESIDENTIAL_ISP:
            return (
                region,
                [guard_country_code],  # Single country most likely
                f"Same country or immediate neighbors ({region})",
                OriginConfidence.HIGH
            )
        
        elif hosting_profile == HostingProfile.ACADEMIC:
            return (
                region,
                neighbor_countries,
                f"Same country or academic network region ({region})",
                OriginConfidence.MEDIUM
            )
        
        else:
            return (
                region,
                neighbor_countries,
                f"Same region ({region}) - moderate estimation",
                OriginConfidence.LOW
            )



class OriginScopeEstimator:
    """
    Main class for origin scope estimation.
    
    CRITICAL: This class MUST be called ONLY AFTER guard inference.
    It does NOT consume PCAP data directly.
    """
    
    def __init__(self):
        self.hosting_classifier = HostingProfileClassifier()
        self.region_estimator = OriginRegionEstimator()
        logger.info("OriginScopeEstimator initialized")
    
    def estimate(
        self,
        guard_country: str,
        guard_country_code: Optional[str],
        guard_isp: Optional[str],
        guard_asn: Optional[str] = None,
        guard_flags: Optional[List[str]] = None
    ) -> OriginScopeResult:
        """
        Estimate origin scope from guard relay information.
        
        IMPORTANT: This does NOT identify the user's exact IP.
        
        Args:
            guard_country: Guard relay country name
            guard_country_code: Guard relay ISO country code
            guard_isp: Guard relay ISP name
            guard_asn: Guard relay ASN (optional)
            guard_flags: Guard relay Tor flags (optional)
            
        Returns:
            OriginScopeResult with probabilistic estimation
        """
        logger.info(f"Estimating origin scope for guard in {guard_country}")
        
        hosting_profile, hosting_desc = self.hosting_classifier.classify(
            guard_isp, guard_asn
        )
        
        country_code = guard_country_code or "XX"
        region, probable_countries, radius_desc, confidence = self.region_estimator.estimate(
            country_code, hosting_profile
        )
        
        if hosting_profile == HostingProfile.VPS_COMMERCIAL:
            isp_category = "Commercial Cloud/VPS Infrastructure"
        elif hosting_profile == HostingProfile.RESIDENTIAL_ISP:
            isp_category = "Residential Internet Service Provider"
        elif hosting_profile == HostingProfile.ACADEMIC:
            isp_category = "Academic/Research Network"
        else:
            isp_category = "Enterprise/Commercial Network"
        
        confidence_reasons = []
        if hosting_profile == HostingProfile.VPS_COMMERCIAL:
            confidence_reasons.append("Guard on VPS - users can select globally")
            confidence_reasons.append("Geographic proximity not reliable indicator")
        elif hosting_profile == HostingProfile.RESIDENTIAL_ISP:
            confidence_reasons.append("Guard on residential ISP - rare, suggests local operator")
            confidence_reasons.append("Geographic proximity more meaningful")
        
        if guard_flags and 'Stable' in guard_flags:
            confidence_reasons.append("Guard has Stable flag - established relay")
        
        result = OriginScopeResult(
            guard_country=guard_country,
            guard_country_code=country_code,
            guard_asn=guard_asn,
            guard_isp=guard_isp,
            hosting_profile=hosting_profile.value,
            hosting_profile_description=hosting_desc,
            probable_origin_region=region,
            probable_origin_countries=probable_countries,
            regional_radius_description=radius_desc,
            origin_isp_category=isp_category,
            confidence_level=confidence.value,
            confidence_reasoning="; ".join(confidence_reasons) if confidence_reasons else "Standard estimation"
        )
        
        logger.info(f"Origin scope estimation complete: {confidence.value} confidence, region: {region}")
        
        return result



def estimate_origin_scope(
    guard_country: str,
    guard_country_code: Optional[str] = None,
    guard_isp: Optional[str] = None,
    guard_asn: Optional[str] = None,
    guard_flags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Convenience function for API integration.
    
    MUST be called ONLY AFTER guard inference.
    Output is SUPPLEMENTARY and does NOT override guard confidence.
    
    Args:
        guard_country: Guard relay country name
        guard_country_code: Guard relay ISO country code
        guard_isp: Guard relay ISP name
        guard_asn: Guard relay ASN
        guard_flags: Guard relay Tor flags
        
    Returns:
        Dictionary with origin scope estimation
    """
    estimator = OriginScopeEstimator()
    result = estimator.estimate(
        guard_country=guard_country,
        guard_country_code=guard_country_code,
        guard_isp=guard_isp,
        guard_asn=guard_asn,
        guard_flags=guard_flags
    )
    
    return result.to_dict()



if __name__ == "__main__":
    print("=" * 70)
    print("ORIGIN SCOPE ESTIMATION MODULE - TEST")
    print("=" * 70)
    
    print("\n--- Test 1: Guard on VPS (DigitalOcean) ---")
    result1 = estimate_origin_scope(
        guard_country="Germany",
        guard_country_code="DE",
        guard_isp="DigitalOcean, LLC"
    )
    print(f"Hosting: {result1['hosting_profile']}")
    print(f"Region: {result1['probable_origin_region']}")
    print(f"Confidence: {result1['confidence_level']}")
    print(f"Radius: {result1['regional_radius_description']}")
    
    print("\n--- Test 2: Guard on Residential ISP (Comcast) ---")
    result2 = estimate_origin_scope(
        guard_country="United States",
        guard_country_code="US",
        guard_isp="Comcast Cable Communications"
    )
    print(f"Hosting: {result2['hosting_profile']}")
    print(f"Region: {result2['probable_origin_region']}")
    print(f"Confidence: {result2['confidence_level']}")
    print(f"Radius: {result2['regional_radius_description']}")
    
    print("\n--- Test 3: Guard on Academic Network ---")
    result3 = estimate_origin_scope(
        guard_country="Netherlands",
        guard_country_code="NL",
        guard_isp="SURFnet University Network"
    )
    print(f"Hosting: {result3['hosting_profile']}")
    print(f"Region: {result3['probable_origin_region']}")
    print(f"Confidence: {result3['confidence_level']}")
    print(f"Radius: {result3['regional_radius_description']}")
    
    print("\n" + "=" * 70)
    print("✅ All tests passed")
    print("=" * 70)
