use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;
use std::str;

const VOWELS_SPACES: &str = "aeiouAEIOU ";

struct GuessResult {
    key: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
}

#[allow(dead_code)]
fn hex_b64(hex_in: &str) -> Option<String> {
    match hex::decode(hex_in) {
        Ok(bytes) => Some(base64::encode(bytes)),
        _ => None
    }
}

#[allow(dead_code)]
fn xor_bytes(bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut out = bytes.clone();
    for i in 0..(bytes.len()) {
        out[i] ^= key[i % key.len()]
    }
    out
}

#[allow(dead_code)]
fn pct_bytes(needles: &Vec<u8>, haystack: &Vec<u8>) -> usize {
    let h = BTreeSet::from_iter(needles.iter());
    100 * haystack.iter().filter(|i| h.contains(*i)).count() / haystack.len()
}

#[allow(dead_code)]
fn simple_dict_attack(input: &Vec<u8>) -> (u8, usize) {
    let mut guess = 0;
    let mut guess_score = 0;
    let needles = VOWELS_SPACES.as_bytes().to_vec();
    for i in 0..127 {
        let decoded = xor_bytes(&input, &vec![i]);
        let p = pct_bytes(&needles, &decoded);
        if p > guess_score {
            guess = i;
            guess_score = p;
        }
    }
    (guess, guess_score)
}

#[allow(dead_code)]
fn detect_single_char_xor(path: &str) -> GuessResult {
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
        where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    };

    let mut guess = vec![];
    let mut guess_score = 0;
    let mut guess_key = 0u8;
    for line in read_lines(&path).unwrap() {
        match line {
            Ok(l) => {
                let bytes = &hex::decode(l).unwrap();
                let (k, score) = simple_dict_attack(bytes);
                if score > guess_score {
                    guess = bytes.clone();
                    guess_score = score;
                    guess_key = k;
                }
            }
            _ => {}
        };
    };
    GuessResult{
        key: vec![guess_key],
        input: guess.clone(),
        output: xor_bytes(&guess, &vec![guess_key])
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_b64() {
        const HEX_IN: &'static str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        const B64_OUT: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(hex_b64(HEX_IN).unwrap(), B64_OUT)
    }

    #[test]
    fn test_fixed_xor() {
        assert_eq!(xor_bytes(&vec![3], &vec![247]), vec![244 as u8]);
        let test_in = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let test_key = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let test_out = hex::decode("746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(xor_bytes(&test_in.to_vec(), &test_key.to_vec()), test_out.to_vec())
    }

    #[test]
    fn test_pct_bytes() {
        let needles = VOWELS_SPACES.as_bytes().to_vec();
        let haystack = "The QUICK brown FOX jumps OVER the lazy DOG".as_bytes().to_vec();
        assert_eq!(pct_bytes(&needles, &haystack), 44)
    }

    #[test]
    fn test_simple_dict_attack() {
        let input = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();
        let guess = simple_dict_attack(&input);
        println!("{:?}: {:?}", guess.0 as char, str::from_utf8(&xor_bytes(&input, &vec![guess.0])).unwrap());
    }

    #[test]
    fn test_detect_single_char_xor() {
        let r = detect_single_char_xor("data/4.txt");
        println!("key: {:?}, decoded: {:?}\nOriginal line: {:?}", r.key, str::from_utf8(&r.output).unwrap(), hex::encode(r.input))
    }

    #[test]
    fn test_repeating_xor() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes().to_vec();
        let key = "ICE".as_bytes().to_vec();
        let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(hex::encode(xor_bytes(&input, &key)), output);
    }
}