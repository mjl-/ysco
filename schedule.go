package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Schedule []dayHour

type dayHour struct {
	Days  []time.Weekday
	Hours []int
}

// Next returns the first time >= now that matches the schedule.
func (s Schedule) Next(now time.Time) time.Time {
	if len(s) == 0 {
		return now
	}

	nowhour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.Local)

	// Stupid brute force through all options.
	var first time.Time
	for _, dh := range s {
		for _, d := range dh.Days {
			dt := now
			for dt.Weekday() != d {
				dt = dt.AddDate(0, 0, 1)
			}
			for _, h := range dh.Hours {
				ht := time.Date(dt.Year(), dt.Month(), dt.Day(), h, 0, 0, 0, time.Local)
				if ht.Equal(nowhour) {
					ht = now
				} else if ht.Before(now) {
					ht = time.Date(dt.Year(), dt.Month(), dt.Day()+7, h, 0, 0, 0, time.Local)
				}
				if first.IsZero() || ht.Before(first) {
					first = ht
				}
			}
		}
	}
	return first
}

func parseDayHour(s string) (dayHour, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return dayHour{}, fmt.Errorf("empty day-hours")
	}
	t := strings.Split(s, " ")
	if len(t) > 2 || t[0] == "" || (len(t) == 2 && t[1] == "") {
		return dayHour{}, fmt.Errorf("too many spaces in day-hours %q", s)
	}

	var err error

	var days []time.Weekday
	if !(t[0][0] >= '0' && t[0][0] <= '9') {
		days, err = parseDays(t[0])
		if err != nil {
			return dayHour{}, fmt.Errorf("parsing days: %v", err)
		}
		t = t[1:]
	} else {
		days = []time.Weekday{
			time.Sunday,
			time.Monday,
			time.Tuesday,
			time.Wednesday,
			time.Thursday,
			time.Friday,
			time.Saturday,
		}
	}

	var hours []int
	if len(t) == 0 {
		hours = make([]int, 24)
		for i := range 24 {
			hours[i] = i
		}
	} else {
		hours, err = parseHours(t[0])
		if err != nil {
			return dayHour{}, fmt.Errorf("bad hours: %v", err)
		}
	}

	return dayHour{days, hours}, nil
}

var weekdays = map[string]time.Weekday{
	"su": time.Sunday,
	"mo": time.Monday,
	"tu": time.Tuesday,
	"we": time.Wednesday,
	"th": time.Thursday,
	"fr": time.Friday,
	"sa": time.Saturday,
}

func parseDays(s string) (days []time.Weekday, rerr error) {
	for _, e := range strings.Split(s, ",") {
		t := strings.Split(e, "-")
		if len(t) > 2 {
			return nil, fmt.Errorf("too many dashes in %q", e)
		}
		start, ok := weekdays[t[0]]
		if !ok {
			return nil, fmt.Errorf("unknown weekday %q", t[0])
		}
		if len(t) == 1 {
			days = append(days, start)
			continue
		}
		end, ok := weekdays[t[1]]
		if !ok {
			return nil, fmt.Errorf("unknown weekday %q", t[1])
		}
		for {
			days = append(days, start)
			if start == end {
				break
			}
			start = (start + 1) % time.Weekday(len(weekdays))
		}
	}
	return days, nil
}

func parseHours(s string) (hours []int, rerr error) {
	for _, e := range strings.Split(s, ",") {
		t := strings.Split(e, "-")
		if len(t) != 2 {
			return nil, fmt.Errorf("need two dashes for hours in %q", e)
		}
		start, err := strconv.ParseUint(t[0], 10, 32)
		if err == nil && start > 23 {
			err = fmt.Errorf("start hour must be between 0 and 23")
		}
		if err != nil {
			return nil, fmt.Errorf("parsing hour %q: %v", t[0], err)
		}
		end, err := strconv.ParseUint(t[1], 10, 32)
		if err == nil && end > 24 {
			err = fmt.Errorf("end hour must be between 0 and 24")
		} else if err == nil && end <= start {
			err = fmt.Errorf("for hour range, end must be > than start")
		}
		if err != nil {
			return nil, fmt.Errorf("parsing hour %q: %v", t[1], err)
		}
		for ; start < end; start++ {
			hours = append(hours, int(start))
		}
	}
	return hours, nil
}
