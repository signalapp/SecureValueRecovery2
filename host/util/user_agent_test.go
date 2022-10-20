// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"reflect"
	"testing"

	"github.com/armon/go-metrics"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		userAgent string
		parsed    *UserAgent
	}{
		{"Signal-Android/4.68.3 Android/25", &UserAgent{PlatformAndroid, "4.68.3", "Android/25"}},
		{"This is obviously not a reasonable User-Agent string.", nil},
		{"Signal-Android/4.68.3", &UserAgent{PlatformAndroid, "4.68.3", ""}},
		{"Signal-Desktop/1.2.3 Linux", &UserAgent{PlatformDesktop, "1.2.3", "Linux"}},
		{"Signal-Desktop/1.2.3 macOS", &UserAgent{PlatformDesktop, "1.2.3", "macOS"}},
		{"Signal-Desktop/1.2.3 Windows", &UserAgent{PlatformDesktop, "1.2.3", "Windows"}},
		{"Signal-Desktop/1.2.3", &UserAgent{PlatformDesktop, "1.2.3", ""}},
		{"Signal-Desktop/1.32.0-beta.3", &UserAgent{PlatformDesktop, "1.32.0-beta.3", ""}},
		{"Signal-iOS/3.9.0 (iPhone; iOS 12.2; Scale/3.00)", &UserAgent{PlatformIOS, "3.9.0", "(iPhone; iOS 12.2; Scale/3.00)"}},
		{"Signal-iOS/3.9.0 iOS/14.2", &UserAgent{PlatformIOS, "3.9.0", "iOS/14.2"}},
		{"Signal-iOS/3.9.0", &UserAgent{PlatformIOS, "3.9.0", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			parsed, _ := ParseUserAgent(tt.userAgent)
			if !reflect.DeepEqual(parsed, tt.parsed) {
				t.Errorf("ParseUserAgent(%v) = %v, want %v", tt.userAgent, parsed, tt.parsed)
			}
		})
	}
}
func TestParseTags(t *testing.T) {
	tests := []struct {
		userAgent       string
		allowedVersions []string
		tags            []metrics.Label
	}{
		{
			"Signal-Android/4.68.3 Android/25",
			[]string{"4.68.3"},
			[]metrics.Label{{Name: "platform", Value: "android"}, {Name: "clientVersion", Value: "4.68.3"}},
		},
		{
			"Signal-Android/4.68.3 Android/25",
			[]string{"4.68.4", "4.68.3"},
			[]metrics.Label{{Name: "platform", Value: "android"}, {Name: "clientVersion", Value: "4.68.3"}},
		},

		{
			"Signal-Android/4.68.3 Android/25",
			[]string{"4.68.4"},
			[]metrics.Label{{Name: "platform", Value: "android"}},
		},

		{
			"A bad useragent Signal-Android/4.68.3 Android/25",
			[]string{"4.68.3"},
			[]metrics.Label{{Name: "platform", Value: "unknown"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			m := make(map[string]bool)
			for _, version := range tt.allowedVersions {
				m[version] = true
			}
			tags := ParseTagsIncludeVersions(tt.userAgent, AllowedVersions{PlatformAndroid: m})
			if !reflect.DeepEqual(tags, tt.tags) {
				t.Errorf("ParseTags(%v) = %v, want %v", tt.userAgent, tags, tt.tags)
			}
		})
	}

}
