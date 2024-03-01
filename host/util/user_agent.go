// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"errors"
	"regexp"
	"strings"

	"github.com/hashicorp/go-metrics"
)

type Platform string
type AllowedVersions = map[Platform]map[string]bool

const (
	PlatformIOS     = "ios"
	PlatformDesktop = "desktop"
	PlatformAndroid = "android"
)

var uaPattern = regexp.MustCompile("(?i)^Signal-(?P<Platform>Android|Desktop|iOS)/(?P<Version>[^ ]+)( (?P<Specifiers>.+))?$")

type UserAgent struct {
	Platform             Platform
	Version              string
	AdditionalSpecifiers string
}

// Tags returns metric labels that can be used to identify this UserAgent. By default,
// version tags will not be included, however if there are versions of interest an
// allow list may be provided via allowedVersions.
func (ua UserAgent) Tags(allowedVersions AllowedVersions) []metrics.Label {
	labels := []metrics.Label{
		{Name: "platform", Value: string(ua.Platform)},
	}
	if versions, ok := allowedVersions[ua.Platform]; ok && versions[ua.Version] {
		labels = append(labels, metrics.Label{Name: "clientVersion", Value: ua.Version})
	}
	return labels
}

// ParseTags parses a UserAgent string and returns tags that can be used to identify
// the user agent. By default, version tags will not be included, see ParseTagsIncludeVersions
func ParseTags(uaString string) []metrics.Label {
	return ParseTagsIncludeVersions(uaString, nil)
}

// ParseTagsIncludeVersions parses a UserAgent string and returns tags that can be used to identify
// the user agent. Version tags will be included for those specified in AllowedVersions
func ParseTagsIncludeVersions(uaString string, allowedVersions AllowedVersions) []metrics.Label {
	ua, err := ParseUserAgent(uaString)
	if err != nil {
		return []metrics.Label{{Name: "platform", Value: "unknown"}}
	}
	return ua.Tags(allowedVersions)
}

// ParseUserAgent parses a user agent string provided via a User-Agent header
func ParseUserAgent(uaString string) (*UserAgent, error) {
	if len(uaString) == 0 {
		return nil, errors.New("User-Agent string is blank")
	}
	matches := uaPattern.FindStringSubmatch(uaString)
	if len(matches) == 0 {
		return nil, errors.New("unrecognized user agent")
	}
	platform := parsePlatform(matches[uaPattern.SubexpIndex("Platform")])
	version := matches[uaPattern.SubexpIndex("Version")]
	specifiers := strings.TrimSpace(matches[uaPattern.SubexpIndex("Specifiers")])
	return &UserAgent{platform, version, specifiers}, nil
}

func parsePlatform(platform string) Platform {
	switch strings.ToLower(platform) {
	case PlatformDesktop:
		return PlatformDesktop
	case PlatformIOS:
		return PlatformIOS
	case PlatformAndroid:
		return PlatformAndroid
	}
	// should never happen - platform should be already be validated by `uaPattern`
	return "unexpected-parse-failure"
}
