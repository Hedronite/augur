// Package render writes verdicts and errors for people and for machines.
//
// JSON is the canonical form: the same verdict always produces the same
// bytes, matching schema/verdict.v0.json and the A0 expected.json fixtures.
// Human writes the terminal rendering of the same document, sorted the same
// way. Errors renders FieldError values in the house style: where, what,
// how to fix — with bounded excerpts, never raw unbounded input.
package render
