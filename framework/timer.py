#!/usr/bin/env python
"""
The time module allows the rest of the framework to time how long it takes for
certain actions to execute and present this information in both seconds and
human-readable form.
"""

import math
import datetime

from framework.dependency_management.dependency_resolver import BaseComponent
from framework.dependency_management.interfaces import TimerInterface


class Timer(BaseComponent, TimerInterface):

    COMPONENT_NAME = "timer"

    # Dictionary of Timers, Several timers can be set at any given point in
    # time.
    timers = {}

    def __init__(self, datetime_format="%d/%m/%Y-%H:%M"):
        self.register_in_service_locator()
        self.date_time_format = datetime_format

    def start_timer(self, offset='0'):
        self.timers[offset] = {}
        self.timers[offset]['start'] = self.get_current_date_time()
        return self.timers[offset]['start']

    def get_current_date_time_as_str(self):
        return self.get_current_date_time().strftime(self.date_time_format)

    @staticmethod
    def get_current_date_time():
        return datetime.datetime.now()

    def get_elapsed_time(self, offset='0'):
        return datetime.datetime.now() - self.timers[offset]['start']

    def get_time_as_str(self, timedelta):
        microseconds, seconds = math.modf(timedelta.total_seconds())
        seconds = int(seconds)
        miliseconds = int(microseconds * 1000)
        hours = seconds / 3600
        seconds -= 3600 * hours
        minutes = seconds / 60
        seconds -= 60 * minutes
        time_str = ''
        if hours > 0:
            time_str += "%2dh, " % hours
        if minutes > 0:
            time_str += "%2dm, " % minutes
        time_str += "%2ds, %3dms" % (seconds, miliseconds)
        # Strip necessary to get rid of leading spaces sometimes.
        return time_str.strip()

    def get_time_human(self, seconds_str):
        seconds, miliseconds = str(seconds_str).split('.')
        seconds = int(seconds)
        miliseconds = int(miliseconds[0:3])
        hours = seconds / 3600
        seconds -= 3600 * hours
        minutes = seconds / 60
        seconds -= 60 * minutes
        time_str = ''
        if hours > 0:
            time_str += "%2dh, " % hours
        if minutes > 0:
            time_str += "%2dm, " % minutes
        time_str += "%2ds, %3dms" % (seconds, miliseconds)
        # Strip necessary to get rid of leading spaces sometimes.
        return time_str.strip()

    def end_timer(self, offset='0'):
        self.timers[offset]['end'] = self.get_current_date_time()

    def get_elapsed_time_as_str(self, offset='0'):
        elapsed = self.get_elapsed_time(offset)
        self.end_timer(offset)
        return self.get_time_as_str(elapsed)

    def get_start_date_time(self, offset='0'):
        return self.timers[offset]['start']

    def get_end_date_time(self, offset='0'):
        if 'end' not in self.timers[offset].keys():
            self.end_timer(offset)
        return self.timers[offset]['end']

    def get_start_date_time_as_str(self, offset='0'):
        return self.get_start_date_time(offset).strftime(self.date_time_format)

    def get_end_date_time_as_str(self, offset='0'):
        return self.get_end_date_time(offset).strftime(self.date_time_format)
