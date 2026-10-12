//! Limits for everything the other peer sends.
//!
//! The other peer is authenticated, not trusted. Without limits a hostile peer can
//! make the receiver run out of memory or disk.
//!
//! TODO: maximum size of a control packet. `common::receive_packet` reads until the
//!       stream ends and must stop at this limit.
//! TODO: maximum size after decompressing a packet, against gzip bombs.
//! TODO: maximum number of entries and maximum depth of the offered tree, checked in
//!       `destination::validate_offer`.
//! TODO: check the free disk space at the destination against the offered size before
//!       accepting, with a clear message. Count what is already there when resuming.
//! TODO: the data stream must not deliver more bytes than the offer promised.
//! TODO: make the limits constants here, so sender and receiver agree on them, and
//!       test each of them with an oversized input.
