// ============================================================================
// EDGE CASES: TIMEZONE & DATE HANDLING BUGS
// Expected: 18+ issues with dates, timezones, DST, leap years
// ============================================================================

// BUG 1: Using Date() without timezone awareness
function getToday() {
  return new Date().toISOString().split("T")[0];
}
// Returns different dates depending on user's timezone
// At 11 PM PST, returns next day in UTC

// BUG 2: Comparing dates as strings
function isExpired(expiryDate) {
  const now = new Date().toISOString();
  return expiryDate < now; // String comparison!
}
// "2024-11-16" < "2024-2-17" === true (wrong! Feb 17 is later)

// BUG 3: Adding months to date
function addMonths(date, months) {
  const newDate = new Date(date);
  newDate.setMonth(newDate.getMonth() + months);
  return newDate;
}
// addMonths(new Date('2024-01-31'), 1) === March 2nd or 3rd!
// January 31 + 1 month tries to make February 31

// BUG 4: Hardcoded timezone assumption
function scheduleEvent(time) {
  const eventTime = new Date(`2024-11-16 ${time}`);
  return eventTime.getTime();
}
// scheduleEvent("14:00") assumes local timezone
// Breaks for users in different timezones

// BUG 5: Daylight Saving Time not handled
function getBusinessDays(start, end) {
  let days = 0;
  const current = new Date(start);

  while (current < end) {
    if (current.getDay() !== 0 && current.getDay() !== 6) {
      days++;
    }
    current.setDate(current.getDate() + 1); // Assumes 24h days
  }

  return days;
}
// Fails during DST transitions (23 or 25 hour days)

// BUG 6: Unix timestamp in milliseconds vs seconds
function fromTimestamp(timestamp) {
  return new Date(timestamp);
}
// If timestamp is in seconds (1700000000), creates date in 1970
// Should be: new Date(timestamp * 1000)

// BUG 7: Leap year calculation
function isLeapYear(year) {
  return year % 4 === 0;
}
// Wrong for 1900, 2100 (divisible by 100 but not 400)
// Correct: year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0)

// BUG 8: Date arithmetic assuming 30-day months
function addBillingPeriod(date) {
  const newDate = new Date(date);
  newDate.setDate(newDate.getDate() + 30);
  return newDate;
}
// Billing on Jan 1 + 30 days = Jan 31
// But Jan 31 + 30 days = March 2 or 3 (skips February)

// BUG 9: Formatting dates for different locales
function formatDate(date) {
  return `${date.getMonth() + 1}/${date.getDate()}/${date.getFullYear()}`;
}
// Returns MM/DD/YYYY (US format)
// Most of world uses DD/MM/YYYY or YYYY-MM-DD

// BUG 10: Parsing ambiguous date strings
function parseDate(dateStr) {
  return new Date(dateStr);
}
// parseDate("01/02/2024") - is this Jan 2 or Feb 1?
// Depends on locale

// BUG 11: Week number calculation
function getWeekNumber(date) {
  const firstDay = new Date(date.getFullYear(), 0, 1);
  const diff = date - firstDay;
  return Math.ceil(diff / (7 * 24 * 60 * 60 * 1000));
}
// Wrong! Doesn't account for which day is start of week
// ISO 8601 says Monday, US says Sunday

// BUG 12: Storing dates as YYYY-MM-DD strings
function saveAppointment(dateStr, time) {
  const appointment = `${dateStr}T${time}:00`;
  database.save(appointment); // No timezone info!
}
// "2024-11-16T14:00:00" - is this 2pm UTC? Local? Undefined!

// BUG 13: Date comparison with different timezones
function isSameDay(date1, date2) {
  return date1.toDateString() === date2.toDateString();
}
// Compares in local timezone
// date1 in UTC might be different day than date2 in PST

// BUG 14: Age calculation
function calculateAge(birthDate) {
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();

  if (monthDiff < 0) {
    age--;
  }

  return age;
}
// Wrong! Doesn't check day of month
// Born Dec 31, today is Dec 30: appears one year older

// BUG 15: Relative time calculation
function getRelativeTime(timestamp) {
  const diff = Date.now() - timestamp;
  const days = Math.floor(diff / (24 * 60 * 60 * 1000));
  return `${days} days ago`;
}
// Doesn't handle DST transitions
// "24 hours ago" could be yesterday or today depending on DST

// BUG 16: Date range validation
function isValidDateRange(start, end) {
  return start < end;
}
// Compares Date objects (works), but:
function isValidDateRange2(startStr, endStr) {
  return new Date(startStr) < new Date(endStr);
}
// Returns true even if strings are invalid dates
// new Date('invalid') < new Date('also invalid') === false

// BUG 17: Scheduling recurring events
function getNextOccurrence(lastRun) {
  const next = new Date(lastRun);
  next.setDate(next.getDate() + 7); // Next week
  return next;
}
// If lastRun was during DST and next week isn't (or vice versa):
// Event time shifts by 1 hour

// BUG 18: Midnight calculations
function endOfDay(date) {
  const end = new Date(date);
  end.setHours(24, 0, 0, 0); // Midnight
  return end;
}
// setHours(24) rolls over to next day correctly, but:
// Better to use setHours(23, 59, 59, 999) for end-of-day

// BUG 19: Date serialization in JSON
const event = {
  title: "Meeting",
  date: new Date("2024-11-16T14:00:00Z"),
};

const json = JSON.stringify(event);
// date becomes string: "2024-11-16T14:00:00.000Z"

const parsed = JSON.parse(json);
// parsed.date is string, not Date object!
// typeof parsed.date === 'string'

// BUG 20: Unix epoch edge cases
function isValidTimestamp(timestamp) {
  return timestamp > 0;
}
// Rejects dates before 1970-01-01
// Allows timestamps beyond Year 2038 problem (32-bit overflow)

// BUG 21: Date input from user
function parseUserDate(input) {
  const date = new Date(input);
  return date.getTime();
}
// parseUserDate('tomorrow') === NaN
// parseUserDate('2024-02-30') === March 1 or 2 (invalid date auto-adjusts)

// BUG 22: Countdown timer
function getTimeRemaining(endDate) {
  const now = new Date();
  const remaining = endDate - now;

  return {
    hours: Math.floor(remaining / (1000 * 60 * 60)),
    minutes: Math.floor((remaining / (1000 * 60)) % 60),
    seconds: Math.floor((remaining / 1000) % 60),
  };
}
// Doesn't handle negative values (past dates)
// During DST transition, counts wrong

// BUG 23: Scheduling across date line
function scheduleInternationalMeeting(timeUTC) {
  const meeting = new Date(timeUTC);
  const localTime = meeting.toLocaleString();
  return localTime;
}
// Sydney and Los Angeles could be on different calendar dates
// "Monday 9am" in Sydney is "Sunday 3pm" in LA

module.exports = {
  getToday,
  isExpired,
  addMonths,
  scheduleEvent,
  getBusinessDays,
  isLeapYear,
  calculateAge,
  getRelativeTime,
  getWeekNumber,
};
