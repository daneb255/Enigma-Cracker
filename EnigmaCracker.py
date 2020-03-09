#!/usr/bin/env python3

import argparse
import json
from enigma.machine import EnigmaMachine
import re
from threading import Thread
import progressbar
import copy


print("  _____       _                          ____                _             ")
print(" | ____|_ __ (_) __ _ _ __ ___   __ _   / ___|_ __ __ _  ___| | _____ _ __ ")
print(" |  _| | '_ \| |/ _` | '_ ` _ \ / _` | | |   | '__/ _` |/ __| |/ / _ \ '__|")
print(" | |___| | | | | (_| | | | | | | (_| | | |___| | | (_| | (__|   <  __/ |   ")
print(" |_____|_| |_|_|\__, |_| |_| |_|\__,_|  \____|_|  \__,_|\___|_|\_\___|_|   ")
print("                |___/                                                      ")


class BlankLinesHelpFormatter (argparse.HelpFormatter):
    def _split_lines(self, text, width):
        return super()._split_lines(text, width) + ['']
    def _fill_text(self, text, width, indent):
        return ''.join(indent + line for line in text.splitlines(keepends=True))


usage_examples = '''Examples:

./EnigmaCracker.py -p "Hello World" -c '{"Rotors":"II IV V", "Reflector":"B", "Ring":[0, 0, 0], "Plugboard":"AV BS CG DL FU HZ", "Key":"WXC"}'
./EnigmaCracker.py -p "FZFZVEQXCN" -c '{"Rotors":"II IV I", "Reflector":"C", "Ring":[1, 3, 0], "Plugboard":"AB TU ND JK LP XS", "Key":"LKI"}'
./EnigmaCracker.py -a "CIPHERTEXT" -o rotors -b -m I -rp 3
./EnigmaCracker.py -a "CIPHERTEXT" -o output -f rotors -m I -pb
./EnigmaCracker.py -a "IOXJGK" -o output -b -m P -k "WETTER"
./EnigmaCracker.py -a "BIHEVF" -o output -b -m P -k "WETTER" -ip
./EnigmaCracker.py -a "EAEWPX" -o output -b -m P -k "WETTER" -cp "P0 E2 P3"
./EnigmaCracker.py -a "MOV:RGA" -o output -b -m R -e
./EnigmaCracker.py -a "NOBCB.....MHJBD" -o output -b -m R -e
./EnigmaCracker.py -a "CIPHERTEXT" -f output -mk 15
./EnigmaCracker.py -a "KEY" -f output-modifiedkeys -ck
./EnigmaCracker.py -a "CIPHERTEXT" --model '{"Rotors":["I", "II", "III","IV", "V"], "RotorsCount":3,"Duplicates":false,"Reflectors":["B", "C"], "Plugboard":6}' -o output -b -m I -rp 3
./EnigmaCracker.py -r 12 -c '{"Rotors":"II IV V", "Reflector":"B", "Ring":[0, 0, 0], "Plugboard":"AV BS CG DL FU HZ", "Key":"WXC"}'
./EnigmaCracker.py -i
 '''

parser = argparse.ArgumentParser(description='Enigma tool for cryptanalysis', formatter_class=BlankLinesHelpFormatter, epilog=usage_examples)
emcgroup = parser.add_argument_group("Enigma Cracker", "Options for Enigma Cracker")
emcgroup.add_argument("-p", "--process", dest='text_process', type=str, help="Encrypt or decrypt a text")
emcgroup.add_argument("-a", "--attack", dest='text_attack', type=str, help="Attack a ciphertext")
emcgroup.add_argument("-r", "--recover-ring", dest='ring_errors', type=int, help="Recover ring settings. Specify number of first wrong characters")
emcgroup.add_argument("-i", "--notches-informations", dest='notches_informations', action="store_true", help="Print the positions of the turnover notches for each rotor")

edgroup = parser.add_argument_group("Encrypt and Decrypt / ring Recovery", "Options for -p & -r")
edgroup.add_argument("-c", "--configuration", dest='configuration', type=str, help="Enigma configuration for encrypting and decrypting")

agroup = parser.add_argument_group("Attack", "Options for -a")
agroup.add_argument("-o", "--output", dest='output_file', type=str, help="Output file to save found configurations")
agroup.add_argument("-b", "--bruteforce", action="store_true", help="Try all configurations")
agroup.add_argument("-f", "--dictionnary", dest='configuration_file', type=str, help="Try only configurations in a list. List must contain one configuration by line")
agroup.add_argument("-m", "--mode", dest='attack_mode', type=str, help="Attack mode. Can be I / P / R")
agroup.add_argument("-mk", "--modify-keys", dest="modify_keys", type=int, help="Decrease keys using a shift")
agroup.add_argument("-ak", "--all-keys", dest="all_keys",action="store_true", help="Add all keys to each configuration in configuration file")
agroup.add_argument("-ck", "--calculate-keys", dest="calculate_keys", type=str, help="Decipher key using daily key, and store new configuration")
agroup.add_argument("--model", dest='model_configurations', type=str, help="Default configuration is M3, but you can modify it")

igroup = parser.add_argument_group("Attack I", "Options for \"Index of coincidence\" attack")
igroup.add_argument("-rp", "--rotor", dest='N_rotors', type=int, help="Try to find rotors positions. Save firsts N results. Configurations are sorted in ascending order. Can't be used with --plugboard")
igroup.add_argument("-pb", "--plugboard", dest="plugboard",action="store_true", help="Try to find plugboard. Needs rotors positions list. Plugs are sorted in ascending order. Can't be used with --rotor")

pgroup = parser.add_argument_group("Attack P", "Options for \"Known Plaintext\" attack")
pgroup.add_argument("-k", "--known-plaintext", dest='known_plaintext', type=str, help="Find all positions using a known plaintext")
pgroup.add_argument("-ip", "--input-plugboard", dest="input_plugboard", action="store_true", help="Recover some plugboard settings (only if plugs modified input). Can't be use with --cycle-plugboard")
pgroup.add_argument("-cp", "--cycle-plugboard", dest="cycle_plugboard", type=str, help="Find positions even if plugboard was used. Specify all elements after \"P\" (for plaintext) or \"E\" (for encrypted). Can't be used with --input-plugboard")

rgroup = parser.add_argument_group("Attack R", "Options for \"Repetition\" attack")
rgroup.add_argument("-e", "--repeated-text", dest="repeated_text", action="store_true", help="Find all positions if same text is multi-ciphered with same initial configuration. Separate repeated texts with \":\" if they are alongside. If they are distant, replace separating letters by \".\". Specify it using \"--attack\" option")

options = parser.parse_args()


class MissingParameter(Exception):
  pass

class Enigma:
  def __init__(self, configuration):
    self.machine = EnigmaMachine.from_key_sheet(
      rotors = configuration["Rotors"],
      reflector = configuration["Reflector"],
      ring_settings = configuration["Ring"],
      plugboard_settings = configuration["Plugboard"])

  def Process(self, text, key):
    self.machine.set_display(key)
    return self.machine.process_text(text, replace_char=None)



class PositionsBruteforcer:
  def __init__(self, text, model, file, dicobrutekey=False, plugs=False):
    self.text = text
    self.model = model
    self.configuration = ""
    if file:
      if dicobrutekey:
        self.next = self.NextDictBrute
        self.lastkey = "Z" * model["RotorsCount"]
      elif plugs:
        self.lastplug = "YZ"
        self.next = self.NextDictPlug
      else:
        self.next = self.NextDict
      self.lastline = -1
      self.lines = open(file).readlines()
      self.lastconf = ""
    else:
      self.next = self.NextBrute
      self.lastreflector = model["Reflectors"][-1]
      self.lastmachine = -1
      self.lastkey = "Z"*model["RotorsCount"]
      self.rotorslist = [" ".join([model["Rotors"][0]]*model["RotorsCount"])]
      while self.rotorslist[-1] != " ".join([model["Rotors"][-1]]*model["RotorsCount"]):
        i = -1
        lastrotor = self.rotorslist[-1].split(" ")
        while lastrotor[i] == model["Rotors"][-1]:
          lastrotor = lastrotor[:i] +[model["Rotors"][0]] + lastrotor[i:][1:]
          i -= 1
        rotor = lastrotor[:i] + [model["Rotors"][model["Rotors"].index(lastrotor[i])+1]] + lastrotor[i:][1:]
        rotor = " ".join(rotor)
        self.rotorslist.append(rotor)
      if not model["Duplicates"]:
        newrotorslist = []
        for rotor in self.rotorslist:
          rotor = rotor.split(" ")
          if len(rotor) == len(set(rotor)):
            newrotorslist.append(" ".join(rotor))
        self.rotorslist = newrotorslist

  def NextDict(self):
    line = self.lastline + 1
    configuration = json.loads(self.lines[line].replace("\n", ""))
    confWkey = copy.deepcopy(configuration)
    del confWkey["Key"]
    if confWkey != self.lastconf:
      self.myenigma = Enigma(configuration)
    self.lastkey = configuration["Key"]
    unencrypted = self.myenigma.Process(self.text, self.lastkey)
    self.lastline = line
    self.lastconf = confWkey
    return unencrypted, configuration

  def NextBrute(self):
    if self.lastkey == "Z"*self.model["RotorsCount"]:
      if self.lastreflector != self.model["Reflectors"][-1]:
        self.configuration["Reflector"] = self.model["Reflectors"][self.model["Reflectors"].index(self.lastreflector)+1]
      else:
        self.lastmachine += 1
        self.configuration = {"Rotors":self.rotorslist[self.lastmachine],"Reflector":self.model["Reflectors"][0], "Ring":[0]*self.model["RotorsCount"], "Plugboard":""}
      self.lastreflector = self.configuration["Reflector"]
      self.lastkey = "A"*self.model["RotorsCount"]
      self.myenigma = Enigma(self.configuration)
    else:
      i = -1
      while self.lastkey[i] == "Z":
        self.lastkey = self.lastkey[:i] + "A" + self.lastkey[i:][1:]
        i -= 1
      self.lastkey = self.lastkey[:i] + chr(ord(self.lastkey[i])+1) + self.lastkey[i:][1:]
    unencrypted = self.myenigma.Process(self.text, self.lastkey)
    self.configuration["Key"] = self.lastkey
    conf = self.configuration
    return unencrypted, conf

  def NextDictBrute(self):
    if self.lastkey == "Z"*self.model["RotorsCount"]:
      line = self.lastline + 1
      configuration = json.loads(self.lines[line].replace("\n", ""))
      self.myenigma = Enigma(configuration)
      self.lastline = line
      self.lastconf = configuration
      self.lastkey = "A"*self.model["RotorsCount"]
    else:
      i = -1
      while self.lastkey[i] == "Z":
        self.lastkey = self.lastkey[:i] + "A" + self.lastkey[i:][1:]
        i -= 1
      self.lastkey = self.lastkey[:i] + chr(ord(self.lastkey[i])+1) + self.lastkey[i:][1:]
    unencrypted = self.myenigma.Process(self.text, self.lastkey)
    currentkey = copy.deepcopy(self.lastkey)
    conf = copy.deepcopy(self.lastconf)
    return unencrypted, conf, currentkey

  def NextDictPlug(self):
    if self.lastplug == "YZ":
      self.lastline += 1
      self.configuration = json.loads(self.lines[self.lastline].replace("\n", ""))
      self.lastplug = "AB"
    else:
      if self.lastplug[1] == "Z":
        self.lastplug = chr(ord(self.lastplug[0])+1) + chr(ord(self.lastplug[0])+2)
      else:
        self.lastplug = self.lastplug[0] + chr(ord(self.lastplug[1])+1)
    self.configuration["Plugboard"] = self.lastplug
    myenigma = Enigma(self.configuration)
    unencrypted = myenigma.Process(self.text, self.configuration["Key"])
    return unencrypted, self.configuration

  def ProcessSameConf(self, text):
    result = self.myenigma.Process(text, self.lastkey)
    return result




def countbruteforce(model_configurations):
  if model_configurations["Duplicates"]:
    rotorscount = len(model_configurations["Rotors"])**model_configurations["RotorsCount"]
  else:
    rotorscount = 1
    for i in range(model_configurations["RotorsCount"]):
      rotorscount = rotorscount*(len(model_configurations["Rotors"])-i)
  keyscount = 26**model_configurations["RotorsCount"]
  reflectorscount = len(model_configurations["Reflectors"])
  return rotorscount*keyscount*reflectorscount, rotorscount*reflectorscount



def calcic(text):
  letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  letterscount = 0
  total = len(text)*(len(text)-1)
  for letter in letters:
    nq = text.count(letter)
    letterscount += nq*(nq-1)
  return letterscount/total



def calcfrequencies(text):
  letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  frequencies = {}
  total = len(text)
  nb = 0
  for letter in letters:
    counter = text.count(letter)
    frequencies[letter] = counter/total
    if counter > 0:
      nb += 1
  return frequencies, nb



def IncreaseKey(key, rotors):
  if len(key) == 0:
    return ""
  else:
    if key[-1] == "Z":
      key = key[:-1] + "A"
    else:
      key = key[:-1] + chr(ord(key[-1])+1)
    if len(key) > 1:
      rotor1 = (rotors[-1] == "I" and key[-1] == "R")
      rotor2 = (rotors[-1] == "II" and key[-1] == "F")
      rotor3 = (rotors[-1] == "III" and key[-1] == "W")
      rotor4 = (rotors[-1] == "IV" and key[-1] == "K")
      rotor5 = (rotors[-1] == "V" and key[-1] == "A")
      rotor678 = ((rotors[-1] == "VI" or rotors[-1] == "VII" or rotors[-1] == "VIII") and (key[-1] == "A" or key[-1] == "N"))
      protor1 = (rotors[-2] == "I" and key[-2] == "Q")
      protor2 = (rotors[-2] == "II" and key[-2] == "E")
      protor3 = (rotors[-2] == "III" and key[-2] == "V")
      protor4 = (rotors[-2] == "IV" and key[-2] == "J")
      protor5 = (rotors[-2] == "V" and key[-2] == "Z")
      protor678 = ((rotors[-2] == "VI" or rotors[-2] == "VII" or rotors[-2] == "VIII") and (key[-2] == "Z" or key[-2] == "M"))
      if (rotor1 or rotor2 or rotor3 or rotor4 or rotor5 or rotor678) and len(rotors) >= 2 and not (rotors[-2] == "Beta" or rotors[-2] == "Gamma"):
        key = IncreaseKey(key[:-1], rotors[:-1]) + key[-1]
      elif (protor1 or protor2 or protor3 or protor4 or protor5 or protor678) and len(rotors) > 2 and not (rotors[-3] == "Beta" or rotors[-3] == "Gamma"):
        if key[-2] == "Z":
          key2 = "A"
        else:
          key2 = chr(ord(key[-2])+1)
        key = IncreaseKey(key[:-2], rotors[:-2]) + key2 + key[-1]
    return key



def DecreaseKey(key, rotors):
  if len(key) == 0:
    return ""
  else:
    if key[-1] == "A":
      key = key[:-1] + "Z"
    else:
      key = key[:-1] + chr(ord(key[-1])-1)
    if len(key) > 1:
      rotor1 = (rotors[-1] == "I" and key[-1] == "Q")
      rotor2 = (rotors[-1] == "II" and key[-1] == "E")
      rotor3 = (rotors[-1] == "III" and key[-1] == "V")
      rotor4 = (rotors[-1] == "IV" and key[-1] == "J")
      rotor5 = (rotors[-1] == "V" and key[-1] == "Z")
      rotor678 = ((rotors[-1] == "VI" or rotors[-1] == "VII" or rotors[-1] == "VIII") and (key[-1] == "Z" or key[-1] == "M"))
      protor1 = (rotors[-2] == "I" and key[-2] == "R")
      protor2 = (rotors[-2] == "II" and key[-2] == "F")
      protor3 = (rotors[-2] == "III" and key[-2] == "W")
      protor4 = (rotors[-2] == "IV" and key[-2] == "K")
      protor5 = (rotors[-2] == "V" and key[-2] == "A")
      protor678 = ((rotors[-2] == "VI" or rotors[-2] == "VII" or rotors[-2] == "VIII") and (key[-2] == "A" or key[-2] == "N"))
      if (rotor1 or rotor2 or rotor3 or rotor4 or rotor5 or rotor678) and len(rotors) >= 2 and not (rotors[-2] == "Beta" or rotors[-2] == "Gamma"):
        key = DecreaseKey(key[:-1], rotors[:-1]) + key[-1]
      elif (protor1 or protor2 or protor3 or protor4 or protor5 or protor678) and len(rotors) > 2 and not (rotors[-3] == "Beta" or rotors[-3] == "Gamma"):
        if key[-2] == "A":
          key2 = "Z"
        else:
          key2 = chr(ord(key[-2])-1)
        key = DecreaseKey(key[:-2], rotors[:-2]) + key2 + key[-1]
    return key



def AllKeys(dictionnary, model, nbpos):
  bar = progressbar.ProgressBar(max_value=nbpos)
  bruteforcer = PositionsBruteforcer("A", model, dictionnary, dicobrutekey=True)
  confs = []
  for i in range(int(nbpos)):
    unencrypted, conf, newkey = bruteforcer.NextDictBrute()
    conf["Key"] = newkey
    confs.append(json.dumps(conf))
    bar.update(i)
  bar.finish()
  f= open(dictionnary + "-allkeys", "a")
  confs = set(confs)
  for conf in confs:
    f.write(conf+"\n")
  f.close()



def ModifyKeys(shift, dictionnary, nbpos):
  bar = progressbar.ProgressBar(max_value=nbpos)
  lines = open(dictionnary).readlines()
  confs = []
  for i in range(int(nbpos)):
    conf = json.loads(lines[i].replace("\n", ""))
    for n in range(shift):
      newkey = DecreaseKey(conf["Key"], conf["Rotors"].split(" "))
      conf["Key"] = newkey
    confs.append(conf)
    bar.update(i)
  bar.finish()
  f=open(dictionnary+"-modifiedkeys", "a")
  for conf in confs:
    f.write(json.dumps(conf) + "\n")
  f.close()



def CalcKeys(cipheredkey, dictionnary, nbpos):
  bar = progressbar.ProgressBar(max_value=nbpos)
  lines = open(dictionnary).readlines()
  confs = []
  for i, line in enumerate(lines):
    conf = json.loads(line.replace("\n", ""))
    machine = Enigma(conf)
    clearkey = machine.Process(cipheredkey, conf["Key"])
    conf["Key"] = clearkey
    confs.append(conf)
    bar.update(i)
  bar.finish()
  f=open(dictionnary+"-calckeys", "a")
  for conf in confs:
    f.write(json.dumps(conf)+"\n")
  f.close()



def rotor_coincidence_attack(ciphertext, number2save, dictionnary, model, nbpos, ofile):
  bar = progressbar.ProgressBar(max_value=nbpos)
  bruteforcer = PositionsBruteforcer(ciphertext, model, dictionnary)
  ics = [0]*number2save
  confs = [""]*number2save
  for i in range(int(nbpos)):
    unencrypted, conf = bruteforcer.next()
    unencryptedIC = calcic(unencrypted)
    if ics.count(0):
      index = ics.index(0)
      ics[index] = unencryptedIC
      confs[index] = json.dumps(conf)
      ics, confs = (list(t) for t in zip(*sorted(zip(ics, confs))))
    else:
      for n, ic in enumerate(ics):
        if unencryptedIC > ic:
          ics = [unencryptedIC] + ics[1:]
          confs = [json.dumps(conf)] + confs[1:]
          ics, confs = (list(t) for t in zip(*sorted(zip(ics, confs))))
          break
    bar.update(i)
  bar.finish()
  f=open(ofile, "a")
  for conf in confs:
    f.write(conf + "\n")
  f.close()



def plugboard_coincidence_attack(ciphertext, model, dictionnary, nblines, ofile):
  bar = progressbar.ProgressBar(max_value=((26*25)/2)*nblines)
  bruteforcer = PositionsBruteforcer(ciphertext, model, dictionnary, plugs=True)
  nbplugs = model["Plugboard"]
  confs = []
  for i in range(int(nblines)):
    plugs = []
    ics = []
    for n in range(int((26*25)/2)):
      unencrypted, conf = bruteforcer.NextDictPlug()
      ics.append(calcic(unencrypted))
      plugs.append(conf["Plugboard"])
      bar.update(i*((26*25)/2)+n)
    ics, plugs = (list(t) for t in zip(*sorted(zip(ics, plugs))))
    validplugs = " ".join(plugs[-model["Plugboard"]:])
    conf["Plugboard"] = validplugs
    confs.append(json.dumps(conf))
  bar.finish()
  f=open(ofile, "a")
  for conf in confs:
    f.write(conf + "\n")
  f.close()



def plaintextattack(ciphertext, known_plaintext, input_plugboard, cycle_plugboard, dictionnary, model, nbpos, ofile):
  bar = progressbar.ProgressBar(max_value=nbpos)
  bruteforcer = PositionsBruteforcer(ciphertext, model, dictionnary)
  confs = []
  for i in range(int(nbpos)):
    unencrypted, conf = bruteforcer.next()
    if unencrypted == known_plaintext:
      confs.append(json.dumps(conf))

    elif input_plugboard:
      plugs = []
      valid = True
      for n,uchar in enumerate(unencrypted):
        pchar = known_plaintext[n]
        if uchar != pchar and not uchar + pchar in plugs and not pchar + uchar in plugs:
          r = re.compile("."+pchar+"|"+pchar+"."+"|"+"."+uchar+"|"+uchar+".")
          if list(filter(r.match, plugs)):
            valid = False
            break
          plugs.append(uchar+pchar)
        elif uchar == pchar:
          r = re.compile("."+pchar+"|"+pchar+".")
          if list(filter(r.match, plugs)):
            valid = False
            break
      if valid and len(plugs) <= model["Plugboard"]:
        conf["Plugboard"] = " ".join(plugs)
        testenigma = Enigma(conf)
        if testenigma.Process(ciphertext, conf["Key"]) == known_plaintext:
          confs.append(json.dumps(conf))
        conf["Plugboard"] = ""

    elif cycle_plugboard:
      celements = cycle_plugboard.split(" ")
      valid = True
      for n, celement in enumerate(celements):
        if n == len(celements)-1:
          nextcelement = celements[0]
        else:
          nextcelement = celements[n+1]
        if celement[0] == "P":
          currentchar = ciphertext[int(celement[1])]
        elif celement[0] == "E":
          currentchar = unencrypted[int(celement[1])]
        if nextcelement[0] == "P":
          nextchar = unencrypted[int(nextcelement[1])]
        elif nextcelement[0] == "E":
          nextchar = ciphertext[int(nextcelement[1])]
        if currentchar != nextchar:
          valid = False
      if valid:
        confs.append(json.dumps(conf))

    bar.update(i)
  bar.finish()
  f=open(ofile, "a")
  for conf in confs:
    f.write(conf + "\n")
  f.close()



def repetitionattack(repeated_text, dictionnary, model, nbpos, ofile):
  bar = progressbar.ProgressBar(max_value=nbpos)
  if ":" in repeated_text:
    splited = repeated_text.split(":")
    distances = [0]*len(splited)
  elif "." in repeated_text:
    splited = repeated_text.split(".")
    distances = []
    counter = 0
    for split in splited:
      if split == "":
        counter +=1
      if split != "":
        distances.append(counter+1)
        counter = 0
    distances = distances[1:]
    distances.append(0)
    splited = list(filter(None, splited))
  else:
    raise MissingParameter("Repeated text is not in valid format, please use --help")
  bruteforcer = PositionsBruteforcer(splited[0], model, dictionnary)
  confs = []
  for i in range(int(nbpos)):
    unencrypted, conf = bruteforcer.next()
    query = ""
    for n in range(len(splited)):
      query += unencrypted+"x"*distances[n]
    reencrypted = bruteforcer.ProcessSameConf(query)
    splitedreencrypted = []
    debut = 0
    fin = len(splited[0])
    for ni in range(len(splited)):
      splitedreencrypted.append(reencrypted[debut:fin])
      debut = fin + distances[ni]
      fin = debut + len(splited[0])
    if splitedreencrypted == splited:
      confs.append(json.dumps(conf))
    bar.update(i)
  bar.finish()
  f=open(ofile, "a")
  for conf in confs:
    f.write(conf + "\n")
  f.close()



def process(options):
  configuration = json.loads(options.configuration)
  print("Configuration :")
  print("Rotors : " + configuration["Rotors"])
  print("Reflector : " + configuration["Reflector"])
  print("ring : " + " ".join([str(ring) for ring in configuration["Ring"]]))
  print("Plugboard : " + configuration["Plugboard"])
  print("Key : " + configuration["Key"])
  print("Processing text using specified configuration...")
  machine = Enigma(configuration)
  text = machine.Process(options.text_process, configuration["Key"])
  ic = calcic(text)
  print("Result (IC : " + str(ic) + "):\n")
  print(text)



def attack(options):
  if options.attack_mode != "R":
    text_attack = re.sub("[^a-zA-Z]+", "", options.text_attack).upper()
  else:
    text_attack = options.text_attack
  if options.model_configurations:
    model_configurations = json.loads(options.model_configurations)
  else:
    model_configurations = {"Rotors":["I", "II", "III", "IV", "V"], "RotorsCount":3, "Duplicates":False, "Reflectors":["B", "C"], "Plugboard":6}
  print("Selected model :")
  print("Rotors : " + " ".join(model_configurations["Rotors"]))
  print("Rotors count : " + str(model_configurations["RotorsCount"]))
  print("Duplicates : " + str(model_configurations["Duplicates"]))
  print("Reflectors : " + " ".join(model_configurations["Reflectors"]))
  print("Number of plugs in plugboard : " + str(model_configurations["Plugboard"]))

  if options.bruteforce:
    dictionnary = None
    nbpos, nbmachines = countbruteforce(model_configurations)
    print("Enigma Cracker will test " + str(nbpos) + " possibilities (without plugboard)")
  elif options.configuration_file:
    dictionnary = options.configuration_file
    configurations = open(dictionnary).readlines()
    nbpos = len(configurations)
    if options.all_keys:
      print("Calculating all keys (" + str(nbpos*26**model_configurations["RotorsCount"]) + " possibilities) and saving into " + dictionnary + "-allkeys...")
      AllKeys(dictionnary, model_configurations, nbpos*26**model_configurations["RotorsCount"])
      print("\n")
      dictionnary = dictionnary + "-allkeys"
      configurations = open(dictionnary).readlines()
      nbpos = len(configurations)
    elif options.modify_keys:
      print("Modifing keys (" + str(nbpos) + " configurations) and saving into " + dictionnary + "-modifiedkeys...")
      ModifyKeys(options.modify_keys, dictionnary, nbpos)
      print("\n")
      dictionnary = dictionnary + "-modifiedkeys"
      configurations = open(dictionnary).readlines()
      nbpos = len(configurations)
    elif options.calculate_keys:
      print("Calculating keys (" + str(nbpos) + " configurations) and saving into " + dictionnary + "-calckeys...")
      CalcKeys(options.calculate_keys, dictionnary, nbpos)
      print("\n")
      dictionnary = dictionnary + "-calckeys"
      configurations = open(dictionnary).readlines()
      nbpos = len(configurations)
    if options.plugboard:
      nbpos = ((26*25)/2)*nbpos
    print("Enigma Cracker will test " + str(nbpos) + " possibilities")

  if options.attack_mode == "I":
    if options.N_rotors:
      rotor_coincidence_attack(text_attack, options.N_rotors, dictionnary, model_configurations, nbpos, options.output_file)
    elif options.plugboard:
      if not options.configuration_file:
        raise MissingParameter("You need to use a list of configurations to recover the plugboard, please use --help")
      plugboard_coincidence_attack(text_attack, model_configurations, dictionnary, len(configurations), options.output_file)
  elif options.attack_mode == "P":
    plaintextattack(text_attack, options.known_plaintext.upper(), options.input_plugboard, options.cycle_plugboard, dictionnary, model_configurations, nbpos, options.output_file)
  elif options.attack_mode == "R":
    repetitionattack(text_attack, dictionnary, model_configurations, nbpos, options.output_file)



def Recoverring(options):
  nerrors = options.ring_errors
  conf = json.loads(options.configuration)
  ring = conf["Ring"]
  key = conf["Key"]
  newring = nerrors
  i = -1
  print("Recovering ring settings from :")
  print("Key : " + key)
  print("ring : " + str(ring))
  print("Number of bad characters : " + str(nerrors))
  if nerrors < 26:
    newring = 26-nerrors
  else:
    while newring > 26:
      newring = newring/26
      i -= 1
  newring = int(newring)
  ring[i] = newring
  newkey = key[i]
  for n in range(newring):
    newkey = IncreaseKey(newkey, "")
  conf["Key"] = key[:i] + newkey + key[i:][1:]
  conf["Ring"] = ring
  print("Result : \n")
  print(json.dumps(conf))



try:
  if options.notches_informations:
    print("+---------------+----------------------+")
    print("|     Rotor     | Turnover Position(s) |")
    print("+---------------+----------------------+")
    print("| I             | Q -> R               |")
    print("| II            | E -> F               |")
    print("| IV            | J -> K               |")
    print("| III           | V -> W               |")
    print("| V             | Z -> A               |")
    print("| VI, VII, VIII | Z -> A & M -> N      |")
    print("+---------------+----------------------+")

  elif options.text_process:
    if not options.configuration:
      raise MissingParameter("Missing configuration, please use --help")
    process(options)

  elif options.text_attack:
    if not options.attack_mode and not (options.calculate_keys or options.modify_keys or options.all_keys):
      raise MissingParameter("Missing attack mode, please use --help")
    if (options.calculate_keys or options.modify_keys or options.all_keys) and not options.configuration_file:
      raise MissingParameter("You need to specify a configuration file (--dictionnary), please use --help")
    if not options.bruteforce and not options.configuration_file:
      raise MissingParameter("Missing bruteforce or dictionnary attack mode, please use --help")
    if not options.output_file and not ((options.calculate_keys or options.modify_keys or options.all_keys) and not options.attack_mode):
      raise MissingParameter("Missing output file, please use --help")
    if options.attack_mode == "I" and not options.N_rotors and not options.plugboard:
      raise MissingParameter("Missing \"Index of Coincidence\" attack options (--rotor or --steckerbrett), please use --help")
    if options.attack_mode == "P" and not options.known_plaintext:
      raise MissingParameter("Missing \"Known Plaintext\" attack option (--known-plaintext), please use --help")
    if options.attack_mode == "R" and not options.repeated_text:
      raise MissingParameter("Missing \"Repetition\" attack option (--repeated-text), please use --help")
    attack(options)

  elif options.ring_errors:
    if not options.configuration:
      raise MissingParameter("Missing configuration, please use --help")
    Recoverring(options)

  else:
    raise MissingParameter("Missing options, please use --help")
except MissingParameter as e:
  print(e)
