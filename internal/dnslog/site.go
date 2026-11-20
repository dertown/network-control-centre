package dnslog

import (
	"net/netip"
	"strings"
)

// secondLevel lists common public second-level labels, so "bbc.co.uk" stays whole instead
// of collapsing to "co.uk". It is a short heuristic, not the full public suffix list.
var secondLevel = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "gov": true, "edu": true, "ac": true,
	"or": true, "ne": true, "go": true, "gob": true, "nic": true, "mil": true, "ltd": true, "plc": true,
}

// localSuffixes are names that never leave the home network.
var localSuffixes = []string{
	".arpa", ".local", ".lan", ".home", ".internal", ".localdomain", ".corp", ".localhost",
}

// Site reduces a query name to the site it belongs to: "r3---sn-abc.googlevideo.com" becomes
// "googlevideo.com". It returns "" for names that are local, reverse lookups or not names.
func Site(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(name, s) {
			return ""
		}
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	keep := 2
	if n >= 3 && len(labels[n-1]) == 2 && secondLevel[labels[n-2]] {
		keep = 3
	}
	if n < keep {
		return name
	}
	return strings.Join(labels[n-keep:], ".")
}

// services names well-known services from the sites they use.
var services = map[string]string{
	"youtube.com": "YouTube", "googlevideo.com": "YouTube", "ytimg.com": "YouTube", "youtu.be": "YouTube",
	"netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nflximg.net": "Netflix", "nflxso.net": "Netflix", "nflxext.com": "Netflix",
	"tiktok.com": "TikTok", "tiktokv.com": "TikTok", "tiktokcdn.com": "TikTok", "tiktokcdn-us.com": "TikTok",
	"instagram.com": "Instagram", "cdninstagram.com": "Instagram",
	"facebook.com": "Facebook", "fbcdn.net": "Facebook", "facebook.net": "Facebook",
	"whatsapp.net": "WhatsApp", "whatsapp.com": "WhatsApp",
	"twitch.tv": "Twitch", "ttvnw.net": "Twitch", "jtvnw.net": "Twitch",
	"spotify.com": "Spotify", "scdn.co": "Spotify", "spotifycdn.com": "Spotify",
	"disneyplus.com": "Disney+", "dssott.com": "Disney+", "bamgrid.com": "Disney+",
	"primevideo.com": "Prime Video", "aiv-cdn.net": "Prime Video", "amazonvideo.com": "Prime Video",
	"hulu.com": "Hulu", "hulustream.com": "Hulu",
	"max.com": "Max", "hbomax.com": "Max",
	"roblox.com": "Roblox", "rbxcdn.com": "Roblox",
	"epicgames.com": "Epic Games", "fortnite.com": "Fortnite",
	"steampowered.com": "Steam", "steamcontent.com": "Steam", "steamstatic.com": "Steam", "steamcommunity.com": "Steam",
	"xboxlive.com": "Xbox Live", "playstation.net": "PlayStation Network", "playstation.com": "PlayStation Network",
	"discord.com": "Discord", "discord.gg": "Discord", "discordapp.com": "Discord", "discordapp.net": "Discord",
	"reddit.com": "Reddit", "redditmedia.com": "Reddit", "redd.it": "Reddit",
	"snapchat.com": "Snapchat", "sc-cdn.net": "Snapchat",
	"twitter.com": "X (Twitter)", "x.com": "X (Twitter)", "twimg.com": "X (Twitter)",
	"zoom.us": "Zoom", "icloud.com": "iCloud", "apple.com": "Apple",
	"pinterest.com": "Pinterest", "pinimg.com": "Pinterest",
	"linkedin.com": "LinkedIn", "licdn.com": "LinkedIn",
}

// Service names the well-known service a site belongs to, or "".
func Service(site string) string { return services[site] }
