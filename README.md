# Enigma-Cracker
Enigma Cracker is an Enigma cryptanalysis tool.

## Setup
### Dependencies
Enigma Cracker needs following packages :
```
pip install py-enigma progressbar2
```
### Install and launch
To install and launch Enigma Cracker :
```
git clone https://github.com/Petitoto/Enigma-Cracker && python3 ./Enigma-Cracker/EnigmaCracker.py
```

## How to use
All help provided in this README is available using `--help` option.
### General options
Enigma cracker can :
- decrypt / encrypt a message using specified configuration
- attack a ciphertext in order to recover rotors and plugboard configuration
- recover ring settings using a number of bad characters
- print informations about the turnover notches for each rotors

```
Enigma Cracker:
  Options for Enigma Cracker

  -p TEXT_PROCESS, --process TEXT_PROCESS
                        Encrypt or decrypt a text

  -a TEXT_ATTACK, --attack TEXT_ATTACK
                        Attack a ciphertext

  -r RING_ERRORS, --recover-ring RING_ERRORS
                        Recover ring settings. Specify number of first wrong
                        characters

  -i, --notches-informations
                        Print the positions of the turnover notches for each
                        rotor
```

### Decrypt and Encrypt / Ring Recovery options
Enigma cracker can encrypt or decrypt a message using specific configuration.<br />
Provide configuration as a JSON-like string, specifying "Rotors", "Reflector", "Ring", "Plugboard", and "Key". All alphabetic chars must be in uppercase (key and plugboard).<br />

```
Encrypt and Decrypt / Ring Recovery:
  Options for -p & -r

  -c CONFIGURATION, --configuration CONFIGURATION
                        Enigma configuration for encrypting and decrypting

```

Examples:

```
./EnigmaCracker.py -p "Hello World" -c '{"Rotors":"II IV V", "Reflector":"B", "Ring":[0, 0, 0], "Plugboard":"AV BS CG DL FU HZ", "Key":"WXC"}'
./EnigmaCracker.py -p "FZFZVEQXCN" -c '{"Rotors":"II IV I", "Reflector":"C", "Ring":[1, 3, 0], "Plugboard":"AB TU ND JK LP XS", "Key":"LKI"}'
```

### Attack options
Enigma cracker can try to recover a ciphertext using :
- index of coincidence attack (I)
- known plaintext attack (P)
- repetition attack (R)


It tests all possible configurations or uses a configuration list to find the ones that could match.<br />
It will save all configurations found in an output file, that you can reuse as a configuration list.<br />
Keys (position of rotors) change for each letter. When using a configuration list, you can modify keys to match the current position (specify number of letter backward).<br />
You can keep only rotors and plugboard configuation and bruteforce all keys for each configuration.<br />
During World War II, key was defined in the firsts characters, ciphered with a daily key. Enigma cracker can first decipher this key and store configuration for the message.<br />
Default model used is a M3 Enigma, but you can modify it. Model should be a JSON-like string, specifying all rotors possibilities ("Rotors"), the number of rotor ("RotorsCount"), if rotors can be duplicated on the same configuation ("Duplicates"), all reflectors possibilities ("Reflectors"), and the maximum number of plugs in plugboard ("Plugboard").<br />
```
Attack:
  Options for -a

  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file to save found configurations

  -b, --bruteforce      Try all configurations

  -f CONFIGURATION_FILE, --dictionnary CONFIGURATION_FILE
                        Try only configurations in a list. List must contain
                        one configuration by line

  -m ATTACK_MODE, --mode ATTACK_MODE
                        Attack mode. Can be I / P / R

  -mk MODIFY_KEYS, --modify-keys MODIFY_KEYS
                        Decrease keys using a shift

  -ak, --all-keys       Add all keys to each configuration in configurations
                        file

  -ck CALCULATE_KEYS, --calculate-keys CALCULATE_KEYS
                        Decipher key using daily key, and store new configuration

  --model MODEL_CONFIGURATIONS
                        Default configuration is M3, but you can modify it
```

Examples:
```
./EnigmaCracker.py -a "CIPHERTEXT" -o output0 -b -m [ATTACK_MODE & OPTIONS]
./EnigmaCracker.py -a "CIPHERTEXT" -o output1 -f output0 -m [ATTACK_MODE & OPTIONS]
./EnigmaCracker.py -a "CIPHERTEXT" -f output1 -mk 15
./EnigmaCracker.py -a "KEY" -f output1-modifiedkeys -ck
./EnigmaCracker.py -a "CIPHERTEXT" --model '{"Rotors":["I", "II", "III","IV", "V"], "RotorsCount":3,"Duplicates":false,"Reflectors":["B", "C"], "Plugboard":6}' -o output -b -m [ATTACK_MODE & OPTIONS]
```

#### Index of coincidence attack (I)
Test configurations and select those with the best index of coincidence.<br />
Enigma Cracker can try rotors possibilities or plugboard possibilities.<br />
When testing rotors, you need to specify the number of configurations to save (plugboard will use "Plugboard" model configuration number).<br />
Note that `--plugboard` option can return incompatible possibilities.<br />
Results are sorted by IC ascending.<br />
```
Attack I:
  Options for "Index of coincidence" attack

  -rp N_ROTORS, --rotor N_ROTORS
                        Try to find rotors positions. Save firsts N results.
                        Configurations are sorted in ascending order. Can't be
                        used with --plugboard

  -pb, --plugboard      Try to find plugboard. Needs rotor positions list.
                        Plugs are sorted in ascending order. Can't be used
                        with --rotor

```

Examples:
```
./EnigmaCracker.py -a "VERYLONGCIPHERTEXT" -o rotors -b -m I -rp 3
./EnigmaCracker.py -a "VERYLONGCIPHERTEXT" -o output -f rotors -m I -pb
```

#### Known Plaintext attack (P)
Test configurations when a cleartext corresponds to ciphertext.<br />
Enigma Cracker can recover plugboard modified only the input of the operator (if "WETTER" has been transformed to "TEWWER").<br />
It can use known plaintext attack while ignoring plugboard settings using a cycle (if "WETTER" is encrypted as "EAEWPX", "WETW" is a cycle as "W" is encrypted "E" at index 0, "E" is decrypted "T" at index 2 and "T" is encrypted "W" at index 3).<br />
```
Attack P:
  Options for "Known Plaintext" attack

  -k KNOWN_PLAINTEXT, --known-plaintext KNOWN_PLAINTEXT
                        Find all positions using a known plaintext

  -ip, --input-plugboard
                        Recover some plugboard settings (only if plugs
                        modified input). Can't be use with --cycle-plugboard

  -cp CYCLE_PLUGBOARD, --cycle-plugboard CYCLE_PLUGBOARD
                        Find positions even if plugboard was used. Specify all
                        elements after "P" (for plaintext) or "E" (for
                        encrypted). Can't be used with --input-plugboard
```

Examples:
```
./EnigmaCracker.py -a "IOXJGK" -o output -b -m P -k "WETTER"
./EnigmaCracker.py -a "BIHEVF" -o output -b -m P -k "WETTER" -ip
./EnigmaCracker.py -a "EAEWPX" -o output -b -m P -k "WETTER" -cp "P0 E2 P3"
```

#### Repetition attack (R)
Test configuration when a cleartext is repeated in different locations.<br />
Specify repeated texts with "." replacing sperating chars (and ":" if they are alongside) in `--attack` option.<br />
```
Attack R:
  Options for "Repetition" attack

  -e, --repeated-text   Find all positions if same text is multi-ciphered with
                        same initial configuration. Separate repeated texts
                        with ":" if they are alongside. If they are distant,
                        replace separating letters by ".". Specify it
                        using "--attack" option
```

Examples:
```
./EnigmaCracker.py -a "MOV:RGA" -o output -b -m R -e
./EnigmaCracker.py -a "NOBCB.....MHJBD" -o output -b -m R -e
```

### Recover ring settings
Enigma cracker can recover ring settings.<br />
When ring is wrong but configuration is good, some chars are mis-deciphered (by blocks). Specify number of wrong chars in each block.<br />

```
Encrypt and Decrypt / Ring Recovery:
  Options for -p & -r

  -c CONFIGURATION, --configuration CONFIGURATION
                        Enigma configuration for encrypting and decrypting

```

Example:
```
./EnigmaCracker.py -r 12 -c '{"Rotors":"II IV V", "Reflector":"B", "Ring":[0, 0, 0], "Plugboard":"AV BS CG DL FU HZ", "Key":"WXC"}'
```

### Print notches informations
Provide cryptanalysis help by printing the positions of the turnover notches for each rotors.<br />

Output of `./EnigmaCracker.py -i`:
```
+---------------+----------------------+
|     Rotor     | Turnover Position(s) |
+---------------+----------------------+
| I             | Q -> R               |
| II            | E -> F               |
| IV            | J -> K               |
| III           | V -> W               |
| V             | Z -> A               |
| VI, VII, VIII | Z -> A & M -> N      |
+---------------+----------------------+
```
