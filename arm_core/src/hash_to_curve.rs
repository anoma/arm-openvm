//! hash_to_curve
//!
//! Structural port of the RustCrypto `k256` implementation
//! <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs>

use alloc::vec::Vec;

use digest::{
    FixedOutput, HashMarker, Output, OutputSizeUser, Update,
    consts::{U32, U136},
    core_api::BlockSizeUser,
};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use openvm_algebra_guest::{Field, IntMod, Reduce};
use openvm_ecc_guest::weierstrass::WeierstrassPoint;
use openvm_k256::{Secp256k1Coord as ScalarPoint, Secp256k1Point};

/// Domain separation tag for the keccak-256 XMD expansion.
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:KECCAK-256_SSWU_RO_";

/// Hash a message to a secp256k1 curve point with unknown discrete log
/// against the generator.
///
/// Mirrors the default `GroupDigest::hash_from_bytes` trait method as bound
/// at `impl GroupDigest for Secp256k1`
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L15-L20>
pub fn hash_from_bytes(msg: &[u8], dst: &[u8]) -> Secp256k1Point {
    let u = hash_to_field(msg, dst, 2);
    let (rx0, ry0) = osswu(&u[0]);
    let (qx0, qy0) = isogeny(rx0, ry0);
    let (rx1, ry1) = osswu(&u[1]);
    let (qx1, qy1) = isogeny(rx1, ry1);
    // TODO! CHECK WHETHER THIS CAN BE MADE SAFE
    let p0 = unsafe { Secp256k1Point::from_xy_nonidentity(qx0, qy0).unwrap() };
    let p1 = unsafe { Secp256k1Point::from_xy_nonidentity(qx1, qy1).unwrap() };
    &p0 + &p1
}

// Port of `impl OsswuMap for FieldElement`'s `PARAMS` constant
// https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L53-L88

/// A' of the isogenous curve y² = x³ + A'x + B'.
fn map_a() -> ScalarPoint {
    ScalarPoint::from_be_bytes_unchecked(&[
        0x3f, 0x87, 0x31, 0xab, 0xdd, 0x66, 0x1a, 0xdc, 0xa0, 0x8a, 0x55, 0x58, 0xf0, 0xf5, 0xd2,
        0x72, 0xe9, 0x53, 0xd3, 0x63, 0xcb, 0x6f, 0x0e, 0x5d, 0x40, 0x54, 0x47, 0xc0, 0x1a, 0x44,
        0x45, 0x33,
    ])
}

/// B' of the isogenous curve (= 1771).
fn map_b() -> ScalarPoint {
    ScalarPoint::from_u32(0x06eb)
}

/// Z = -11 mod p, the SSWU non-residue choice for secp256k1.
fn z_param() -> ScalarPoint {
    ScalarPoint::from_be_bytes_unchecked(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xfc, 0x24,
    ])
}

/// c2 = √(-Z) mod p, precomputed. Used in the SSWU map when g(x₁) has no
/// square root and we fall back to x₂.
fn c2_param() -> ScalarPoint {
    ScalarPoint::from_be_bytes_unchecked(&[
        0x25, 0xe9, 0x71, 0x1a, 0xe8, 0xc0, 0xda, 0xdc, 0x46, 0xfd, 0xbc, 0xb7, 0x2a, 0xad, 0xd8,
        0xf4, 0x25, 0x0b, 0x65, 0x07, 0x30, 0x12, 0xec, 0x80, 0xbc, 0x6e, 0xcb, 0x9c, 0x12, 0x97,
        0x39, 0x75,
    ])
}

// Port of `impl OsswuMap for FieldElement::osswu` body
// https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L89-L131

/// Maps a field element `u` to a point `(x, y)` on the isogenous curve
/// y² = x³ + A'x + B'. The result is mapped to secp256k1 by the isogeny.
fn osswu(u: &ScalarPoint) -> (ScalarPoint, ScalarPoint) {
    let a = map_a();
    let b = map_b();
    let z = z_param();
    let c2 = c2_param();
    let one = ScalarPoint::from_u32(1);
    let zero = ScalarPoint::from_u32(0);

    let tv1 = u.square();
    let tv3 = &z * &tv1;
    let mut tv2 = tv3.square();
    let mut xd = &tv2 + &tv3;
    let x1n = &b * &(&xd + &one);

    let mut neg_a = a.clone();
    neg_a.neg_assign();
    xd = &xd * &neg_a;

    if xd == zero {
        xd = &z * &map_a();
    }

    tv2 = xd.square();
    let gxd = &tv2 * &xd;
    tv2 = &tv2 * &a;

    let mut gx1 = &x1n * &(&tv2 + &x1n.square());
    tv2 = &gxd * &b;
    gx1 = &gx1 + &tv2;

    let mut tv4 = gxd.square();
    tv2 = &gx1 * &gxd;
    tv4 = &tv4 * &tv2;

    let y1 = &pow_c1(&tv4) * &tv2;

    let x2n = &tv3 * &x1n;
    let y2 = &(&(&y1 * &c2) * &tv1) * u;

    tv2 = &y1.square() * &gxd;
    let e2 = tv2 == gx1;

    let mut x = if e2 { x1n.clone() } else { x2n };
    x = &x * &xd.invert();
    let mut y = if e2 { y1 } else { y2 };

    if is_odd(u) != is_odd(&y) {
        y.neg_assign();
    }

    (x, y)
}

/// Port of `impl Sgn0 for FieldElement` (k256 L46–L50):
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L46-L50>
fn is_odd(x: &ScalarPoint) -> bool {
    x.as_le_bytes()[0] & 1 == 1
}

/// Not a direct port of a k256 item — upstream delegates to
/// `FieldElement::sqrt` (internally `pow_vartime`), which isn't exposed by
/// `openvm-k256` at beta.2. We open-code the exponentiation here.
/// The exponent (p-3)/4 is specified by RFC 9380 §I.2.
fn pow_c1(x: &ScalarPoint) -> ScalarPoint {
    // (p-3)/4 as little-endian u64 limbs, where p = 2^256 - 2^32 - 977.
    let c1: [u64; 4] = [
        0xffff_ffff_bfff_ff0b,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ];
    let mut result = ScalarPoint::from_u32(1);
    let mut base = x.clone();
    for limb in c1 {
        let mut bits = limb;
        for _ in 0..64 {
            if bits & 1 == 1 {
                result = &result * &base;
            }
            base = base.square();
            bits >>= 1;
        }
    }
    result
}

// Port of the free `fn isogeny` in k256 (L171–L267):
// https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L171-L267

/// Upstream k256 inlines the polynomial evaluation in its `fn isogeny`;
/// this helper extracts the same logic so the four polynomials share it.
fn horner(coeffs: &[ScalarPoint], x: &ScalarPoint) -> ScalarPoint {
    let mut result = coeffs[coeffs.len() - 1].clone();
    for i in (0..coeffs.len() - 1).rev() {
        result = &(&result * x) + &coeffs[i];
    }
    result
}

/// Numerator of the x-coordinate isogeny map (degree 3).
/// k256 `XNUM` constant at L172–L193:
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L172-L193>
fn xnum() -> [ScalarPoint; 4] {
    [
        ScalarPoint::from_be_bytes_unchecked(&[
            0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
            0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d,
            0xaa, 0xaa, 0xa8, 0xc7,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x07, 0xd3, 0xd4, 0xc8, 0x0b, 0xc3, 0x21, 0xd5, 0xb9, 0xf3, 0x15, 0xce, 0xa7, 0xfd,
            0x44, 0xc5, 0xd5, 0x95, 0xd2, 0xfc, 0x0b, 0xf6, 0x3b, 0x92, 0xdf, 0xff, 0x10, 0x44,
            0xf1, 0x7c, 0x65, 0x81,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x53, 0x4c, 0x32, 0x8d, 0x23, 0xf2, 0x34, 0xe6, 0xe2, 0xa4, 0x13, 0xde, 0xca, 0x25,
            0xca, 0xec, 0xe4, 0x50, 0x61, 0x44, 0x03, 0x7c, 0x40, 0x31, 0x4e, 0xcb, 0xd0, 0xb5,
            0x3d, 0x9d, 0xd2, 0x62,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
            0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d,
            0xaa, 0xaa, 0xa8, 0x8c,
        ]),
    ]
}

/// Denominator of the x-coordinate isogeny map (degree 2; leading coefficient 1).
/// k256 `XDEN` constant at L194–L210:
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L194-L210>
fn xden() -> [ScalarPoint; 3] {
    [
        ScalarPoint::from_be_bytes_unchecked(&[
            0xd3, 0x57, 0x71, 0x19, 0x3d, 0x94, 0x91, 0x8a, 0x9c, 0xa3, 0x4c, 0xcb, 0xb7, 0xb6,
            0x40, 0xdd, 0x86, 0xcd, 0x40, 0x95, 0x42, 0xf8, 0x48, 0x7d, 0x9f, 0xe6, 0xb7, 0x45,
            0x78, 0x1e, 0xb4, 0x9b,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0xed, 0xad, 0xc6, 0xf6, 0x43, 0x83, 0xdc, 0x1d, 0xf7, 0xc4, 0xb2, 0xd5, 0x1b, 0x54,
            0x22, 0x54, 0x06, 0xd3, 0x6b, 0x64, 0x1f, 0x5e, 0x41, 0xbb, 0xc5, 0x2a, 0x56, 0x61,
            0x2a, 0x8c, 0x6d, 0x14,
        ]),
        ScalarPoint::from_u32(1),
    ]
}

/// Numerator of the y-coordinate isogeny map (degree 3).
/// k256 `YNUM` constant at L211–L232:
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L211-L232>
fn ynum() -> [ScalarPoint; 4] {
    [
        ScalarPoint::from_be_bytes_unchecked(&[
            0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84,
            0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b,
            0x8e, 0x38, 0xe2, 0x3c,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0xc7, 0x5e, 0x0c, 0x32, 0xd5, 0xcb, 0x7c, 0x0f, 0xa9, 0xd0, 0xa5, 0x4b, 0x12, 0xa0,
            0xa6, 0xd5, 0x64, 0x7a, 0xb0, 0x46, 0xd6, 0x86, 0xda, 0x6f, 0xdf, 0xfc, 0x90, 0xfc,
            0x20, 0x1d, 0x71, 0xa3,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x29, 0xa6, 0x19, 0x46, 0x91, 0xf9, 0x1a, 0x73, 0x71, 0x52, 0x09, 0xef, 0x65, 0x12,
            0xe5, 0x76, 0x72, 0x28, 0x30, 0xa2, 0x01, 0xbe, 0x20, 0x18, 0xa7, 0x65, 0xe8, 0x5a,
            0x9e, 0xce, 0xe9, 0x31,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12,
            0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f,
            0x38, 0xe3, 0x8d, 0x84,
        ]),
    ]
}

/// Denominator of the y-coordinate isogeny map (degree 3; leading coefficient 1).
/// k256 `YDEN` constant at L233–L254:
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L233-L254>
fn yden() -> [ScalarPoint; 4] {
    [
        ScalarPoint::from_be_bytes_unchecked(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xf9, 0x3b,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x7a, 0x06, 0x53, 0x4b, 0xb8, 0xbd, 0xb4, 0x9f, 0xd5, 0xe9, 0xe6, 0x63, 0x27, 0x22,
            0xc2, 0x98, 0x94, 0x67, 0xc1, 0xbf, 0xc8, 0xe8, 0xd9, 0x78, 0xdf, 0xb4, 0x25, 0xd2,
            0x68, 0x5c, 0x25, 0x73,
        ]),
        ScalarPoint::from_be_bytes_unchecked(&[
            0x64, 0x84, 0xaa, 0x71, 0x65, 0x45, 0xca, 0x2c, 0xf3, 0xa7, 0x0c, 0x3f, 0xa8, 0xfe,
            0x33, 0x7e, 0x0a, 0x3d, 0x21, 0x16, 0x2f, 0x0d, 0x62, 0x99, 0xa7, 0xbf, 0x81, 0x92,
            0xbf, 0xd2, 0xa7, 0x6f,
        ]),
        ScalarPoint::from_u32(1),
    ]
}

/// Port of `isogeny` in k256 (L255–L267 — the evaluation block following
/// the coefficient constants):
/// <https://github.com/RustCrypto/elliptic-curves/blob/2ee79cab879dcc051fb46fe41bace8b3ec87ccad/k256/src/arithmetic/hash2curve.rs#L255-L267>
fn isogeny(rx: ScalarPoint, ry: ScalarPoint) -> (ScalarPoint, ScalarPoint) {
    let x_num = horner(&xnum(), &rx);
    let x_den = horner(&xden(), &rx);
    let y_num = horner(&ynum(), &rx);
    let y_den = horner(&yden(), &rx);
    let qx = &x_num * &x_den.invert();
    let qy = &(&ry * &y_num) * &y_den.invert();
    (qx, qy)
}

/// expand_message_xmd (keccak-256) reduced to `count` secp256k1 base-field elements.
fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<ScalarPoint> {
    let len_in_bytes = count * 48;
    let dsts: &[&[u8]] = &[dst];
    let mut expander =
        ExpandMsgXmd::<OpenVMKeccak256>::expand_message(&[msg], dsts, len_in_bytes).unwrap();

    let mut result = Vec::with_capacity(count);
    let mut chunk = [0u8; 48];
    for _ in 0..count {
        expander.fill_bytes(&mut chunk);
        // `reduce_be_bytes` expects multiple-of-32 input; left-pad the 48-byte
        // chunk to 64 bytes so the reduction treats it as a big-endian integer.
        let mut padded = [0u8; 64];
        padded[16..].copy_from_slice(&chunk);
        result.push(ScalarPoint::reduce_be_bytes(&padded));
    }
    result
}

/// Buffers update bytes and keccak-256-hashes them on finalize, routing through
/// the openvm precompile. Block size is the keccak-256 rate (136 bytes).
#[derive(Default)]
struct OpenVMKeccak256(Vec<u8>);

impl HashMarker for OpenVMKeccak256 {}

impl BlockSizeUser for OpenVMKeccak256 {
    type BlockSize = U136;
}

impl OutputSizeUser for OpenVMKeccak256 {
    type OutputSize = U32;
}

impl Update for OpenVMKeccak256 {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for OpenVMKeccak256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&crate::hash::keccak256(&self.0));
    }
}
