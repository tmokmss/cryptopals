const w: u8 = 32;
const n: usize = 624;
const m: usize = 397;
const r: u8 = 31;
const a: u32 = 0x9908b0df;
const u: u8 = 11;
const d: u32 = 0xffffffff;
const s: u8 = 7;
const b: u32 = 0x9d2c5680;
const t: u8 = 15;
const c: u32 = 0xefc60000;
const l: u8 = 18;
const f: u32 = 1812433253;
const lower_mask: u32 = (1 << r) - 1;
const upper_mask: u32 = !lower_mask;

pub struct MT19937 {
    x: [u32; n],
    index: usize,
}

impl MT19937 {
    pub fn new(seed: u32) -> Self {
        let mut x = [0u32; n];
        x[0] = seed;
        for i in 1..n {
            x[i] = f.wrapping_mul(x[i - 1] ^ (x[i - 1] >> (w - 2))) + (i as u32);
        }
        Self { x, index: n }
    }

    pub fn from_state(state: [u32; n]) -> Self {
        Self { x: state, index: n }
    }

    fn twist(&mut self) {
        for i in 0..n {
            let x = (self.x[i] & upper_mask) | ((self.x[(i + 1) % n]) & lower_mask);
            let mut xA = x >> 1;
            if x % 2 != 0 {
                xA ^= a;
            }
            self.x[i] = self.x[(i + m) % n] ^ xA;
        }
        self.index = 0;
    }

    fn temper(x: u32) -> u32 {
        let mut y = x;
        y ^= (y >> u) & d;
        y ^= (y << s) & b;
        y ^= (y << t) & c;
        y ^= y >> l;
        y
    }

    pub fn next(&mut self) -> u32 {
        if self.index >= n {
            assert!(self.index == n, "invalid index");
            self.twist();
        }
        let y = Self::temper(self.x[self.index]);
        self.index += 1;
        y
    }
}

pub fn untemper(y: u32) -> u32 {
    // y0 = y1 ^ y1 >> l;
    let mut x = 0;
    for i in 0..w {
        let yi = y >> (w - i - 1) & 1;
        if i < l {
            x |= yi << w - i - 1;
        } else {
            x |= (yi ^ (x >> (w - (i - l) - 1) & 1)) << w - i - 1
        }
    }
    // y1 = y2 ^ (y2 << t) & c;
    let y: u32 = x;
    x = 0;
    for i in (0..w).rev() {
        let yi = y >> w - i - 1 & 1;
        if i >= w - t {
            x |= yi << w - i - 1;
        } else {
            x |= (yi ^ ((x >> (w - (i + t) - 1) & 1) & (c >> (w - i - 1) & 1))) << w - i - 1;
        }
    }
    // y2 = y3 ^ (y3 << s) & b;
    let y = x;
    x = 0;
    for i in (0..w).rev() {
        let yi = y >> w - i - 1 & 1;
        if i >= w - s {
            x |= yi << w - i - 1;
        } else {
            x |= (yi ^ ((x >> w - (i + s) - 1 & 1) & (b >> w - i - 1 & 1))) << w - i - 1
        }
    }
    // y3 = y4 ^ (y4 >> u) & d;
    let y = x;
    x = 0;
    for i in 0..w {
        let yi = y >> w - i - 1 & 1;
        if i < u {
            x |= yi << w - i - 1;
        } else {
            x |= (yi ^ ((x >> w - (i - u) - 1 & 1) & (d >> w - i - 1 & 1))) << w - i - 1
        }
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937() {
        let mut mt = MT19937::new(1234);
        assert_eq!(822569775, mt.next());

        let mut mt = MT19937::new(1131464071);
        assert_eq!(3521569528, mt.next());
        assert_eq!(1101990581, mt.next());
        assert_eq!(1076301704, mt.next());
        assert_eq!(2948418163, mt.next());
        assert_eq!(3792022443, mt.next());
        assert_eq!(2697495705, mt.next());
        assert_eq!(2002445460, mt.next());
    }

    #[test]
    fn test_tamper() {
        assert_eq!(822569775, MT19937::temper(2260313690));
        assert_eq!(3521569528, MT19937::temper(1065953061));
    }

    #[test]
    fn test_untamper() {
        assert_eq!(2260313690, untemper(822569775));
        assert_eq!(1065953061, untemper(3521569528));
    }
}
