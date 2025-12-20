// Country data with flags (ISO 3166-1 alpha-2)
const COUNTRY_FLAGS = {
    'US': { flag: '🇺🇸', name: 'United States' },
    'DE': { flag: '🇩🇪', name: 'Germany' },
    'NL': { flag: '🇳🇱', name: 'Netherlands' },
    'FR': { flag: '🇫🇷', name: 'France' },
    'GB': { flag: '🇬🇧', name: 'United Kingdom' },
    'CA': { flag: '🇨🇦', name: 'Canada' },
    'CH': { flag: '🇨🇭', name: 'Switzerland' },
    'SE': { flag: '🇸🇪', name: 'Sweden' },
    'FI': { flag: '🇫🇮', name: 'Finland' },
    'RO': { flag: '🇷🇴', name: 'Romania' },
    'RU': { flag: '🇷🇺', name: 'Russia' },
    'UA': { flag: '🇺🇦', name: 'Ukraine' },
    'LU': { flag: '🇱🇺', name: 'Luxembourg' },
    'AT': { flag: '🇦🇹', name: 'Austria' },
    'CZ': { flag: '🇨🇿', name: 'Czech Republic' },
    'PL': { flag: '🇵🇱', name: 'Poland' },
    'AU': { flag: '🇦🇺', name: 'Australia' },
    'JP': { flag: '🇯🇵', name: 'Japan' },
    'SG': { flag: '🇸🇬', name: 'Singapore' },
    'HK': { flag: '🇭🇰', name: 'Hong Kong' },
    'IN': { flag: '🇮🇳', name: 'India' },
    'BR': { flag: '🇧🇷', name: 'Brazil' },
    'IS': { flag: '🇮🇸', name: 'Iceland' },
    'NO': { flag: '🇳🇴', name: 'Norway' },
    'DK': { flag: '🇩🇰', name: 'Denmark' },
    'ES': { flag: '🇪🇸', name: 'Spain' },
    'IT': { flag: '🇮🇹', name: 'Italy' },
    'BE': { flag: '🇧🇪', name: 'Belgium' },
    'IE': { flag: '🇮🇪', name: 'Ireland' },
    'PT': { flag: '🇵🇹', name: 'Portugal' },
    'UNKNOWN': { flag: '🌐', name: 'Unknown Location' }
};

// Free IP geolocation API (ip-api.com)
export async function getIPGeolocation(ip) {
    try {
        // Handle localhost/private IPs
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') || ip === 'localhost') {
            return { country: 'UNKNOWN', countryCode: 'UNKNOWN', city: 'Local Network', flag: '🏠' };
        }

        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp`);
        const data = await response.json();

        if (data.status === 'success') {
            const countryInfo = COUNTRY_FLAGS[data.countryCode] || COUNTRY_FLAGS['UNKNOWN'];
            return {
                country: data.country,
                countryCode: data.countryCode,
                city: data.city || 'Unknown City',
                isp: data.isp || 'Unknown ISP',
                flag: countryInfo.flag,
                countryName: countryInfo.name
            };
        }
    } catch (error) {
        console.warn('Geolocation lookup failed:', error);
    }

    return { country: 'Unknown', countryCode: 'UNKNOWN', city: 'Unknown', flag: '🌐', countryName: 'Unknown Location' };
}

// Get country info from code
export function getCountryInfo(countryCode) {
    return COUNTRY_FLAGS[countryCode] || COUNTRY_FLAGS['UNKNOWN'];
}

export { COUNTRY_FLAGS };
