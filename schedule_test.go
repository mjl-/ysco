package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func init() {
	os.Setenv("TZ", "Europe/Amsterdam")
}

func TestSchedule(t *testing.T) {
	parse := func(s string) (Schedule, error) {
		var sched Schedule
		var err error
		for _, xs := range strings.Split(s, ";") {
			dh, xerr := parseDayHour(xs)
			if xerr != nil {
				err = xerr
				break
			}
			sched = append(sched, dh)
		}
		return sched, err
	}

	check := func(s string, expSched Schedule, expErr bool) {
		t.Helper()
		sched, err := parse(s)
		if (err != nil) != expErr {
			t.Fatalf("err %v, expected error %v", err, expErr)
		}
		if !reflect.DeepEqual(sched, expSched) {
			t.Fatalf("sched:\n%#v\nexpected:\n%#v", sched, expSched)
		}
	}

	check("", nil, true)
	check("mo 1-2", Schedule([]dayHour{{[]time.Weekday{time.Monday}, []int{1}}}), false)
	check("sa-mo,we 9-12; fr 7-8,12-13,18-20", Schedule([]dayHour{
		{[]time.Weekday{time.Saturday, time.Sunday, time.Monday, time.Wednesday}, []int{9, 10, 11}},
		{[]time.Weekday{time.Friday}, []int{7, 12, 18, 19}},
	}), false)
	check("mo", Schedule([]dayHour{{[]time.Weekday{time.Monday}, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}}), false)
	check("9-12", Schedule([]dayHour{
		{[]time.Weekday{time.Sunday, time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday}, []int{9, 10, 11}},
	}), false)

	checkNext := func(s string, now string, expNext string) {
		t.Helper()
		tnow, err := time.Parse(time.UnixDate, now)
		if err != nil {
			t.Fatalf("parsing now: %v", err)
		}
		texp, err := time.Parse(time.UnixDate, expNext)
		if err != nil {
			t.Fatalf("parsing next: %v", err)
		}
		sched, err := parse(s)
		if err != nil {
			t.Fatalf("parsing schedule: %v", err)
		}
		next := sched.Next(tnow)
		if !next.Equal(texp) {
			t.Fatalf("got %v, expected %v", next, texp)
		}
	}

	checkNext("mo", "Mon Oct  7 22:39:30 CEST 2024", "Mon Oct  7 22:39:30 CEST 2024")
	checkNext("mo 23-24", "Mon Oct  7 22:39:30 CEST 2024", "Mon Oct  7 23:00:00 CEST 2024")
	checkNext("mo 8-9", "Mon Oct  7 22:39:30 CEST 2024", "Mon Oct 14  8:00:00 CEST 2024")
	checkNext("8-9", "Mon Oct  7 22:39:30 CEST 2024", "Tue Oct  8  8:00:00 CEST 2024")
	checkNext("we 10-12; mo 23-24", "Mon Oct  7 22:39:30 CEST 2024", "Mon Oct  7 23:00:00 CEST 2024")
}
