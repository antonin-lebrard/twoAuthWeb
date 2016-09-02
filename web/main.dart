// Copyright (c) 2016, Antonin LEBRARD. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

import 'dart:html';

import 'dart:typed_data';
import 'dart:math';
import 'package:otp/otp.dart';
import 'package:cipher/cipher.dart';
import 'package:cipher/impl/client.dart';
import 'package:cipher/params/key_parameter.dart';
import 'package:cipher/params/key_derivators/scrypt_parameters.dart';

InputElement addKeyInput = querySelector("#addKey");
InputElement labelInput = querySelector("#label");
InputElement passwordInput = querySelector("#pass");
DivElement out = querySelector("#output");

void main() {
  initCipher();
  labelInput.onKeyDown.listen((KeyboardEvent evt){
    if (evt.keyCode == 13) {
      evt.preventDefault();
      if (labelInput.value == "" || addKeyInput.value == "" || passwordInput.value == "") {
        print("empty label, key or password value");
        return;
      }
      addKey([passwordInput.value, addKeyInput.value, labelInput.value]);
    }
  });
  addKeyInput.onKeyDown.listen((KeyboardEvent evt){
    if (evt.keyCode == 13){
      evt.preventDefault();
      if (labelInput.value == "" || addKeyInput.value == "" || passwordInput.value == "") {
        print("empty label, key or password value");
        return;
      }
      addKey([passwordInput.value, addKeyInput.value, labelInput.value]);
    }
  });
  passwordInput.onKeyDown.listen((KeyboardEvent evt){
    if (evt.keyCode == 13){
      evt.preventDefault();
      if (passwordInput.value == "") {
        print("empty password value");
        return;
      }
      displayPins(passwordInput.value);
    }
  });
}


void addKey(List<String> args){
  String password      = args[0];
  String generatingKey = args[1];
  String label         = args[2];

  String salt = "geras48t";
  var scryptParams = new ScryptParameters(pow(2,16), 8, 1, 32, new Uint8List.fromList(salt.codeUnits));
  var keyDerivator = new KeyDerivator("scrypt")..init(scryptParams);

  var key = keyDerivator.process(new Uint8List.fromList(password.codeUnits));

  var params = new KeyParameter(key);
  var ivparams = new ParametersWithIV(params, new Uint8List(16));
  var cipher = new BlockCipher("AES/CTR")..init(true, ivparams);

  label = label.replaceAll("-", "~");

  List<String> toEncrypt = new List();
  String temp = label + "";
  while(temp.length > 0){
    if (temp.length < 16) for (int i = temp.length; i < 16; i++) temp += "-";
    toEncrypt.add(temp.substring(0, 16));
    if (temp.length != 0) temp = temp.substring(16, temp.length);
  }

  List<String> toWrite = new List();
  for (int i = 0; i < toEncrypt.length; i++) {
    Uint8List clearBits = new Uint8List.fromList(toEncrypt[i].codeUnits);
    toWrite.add(new String.fromCharCodes(cipher.process(clearBits)));
    params = new KeyParameter(clearBits);
    ivparams = new ParametersWithIV(params, new Uint8List(16));
    cipher.reset();
    cipher.init(true, ivparams);
  }

  label = toWrite.join(" ");

  cipher.reset();
  cipher.init(true, ivparams);

  toEncrypt = new List();
  temp = generatingKey + "";
  while(temp.length > 0){
    if (temp.length < 16) for (int i = temp.length; i < 16; i++) temp += "-";
    toEncrypt.add(temp.substring(0, 16));
    if (temp.length != 0) temp = temp.substring(16, temp.length);
  }

  toWrite = new List();
  for (int i = 0; i < toEncrypt.length; i++){
    Uint8List clearBits = new Uint8List.fromList(toEncrypt[i].codeUnits);
    toWrite.add(new String.fromCharCodes(cipher.process(clearBits)));
    params = new KeyParameter(clearBits);
    ivparams = new ParametersWithIV(params, new Uint8List(16));
    cipher.reset();
    cipher.init(true, ivparams);
  }

  File f;
  int rand;
  do {
    rand = new Random().nextInt(200000);
  } while (window.localStorage.containsKey(rand.toString()+".key"));
  window.localStorage[rand.toString()+".key"] = toWrite.join(" ") + "  " + label;
}

void displayPins(String password) {
  List<String> generatingKeys = new List();
  List<String> labels = new List();
  List<String> keyNames = new List();

  String salt = "geras48t";
  var scryptParams = new ScryptParameters(
      pow(2, 16), 8, 1, 32, new Uint8List.fromList(salt.codeUnits));
  var keyDerivator = new KeyDerivator("scrypt")
    ..init(scryptParams);

  var key = keyDerivator.process(new Uint8List.fromList(password.codeUnits));

  var params = new KeyParameter(key);
  var ivparams = new ParametersWithIV(params, new Uint8List(16));
  var cipher = new BlockCipher("AES/CTR")
    ..init(false, ivparams);

  if (!window.localStorage.keys.any((String key) => key.endsWith(".key"))) {
    print("no keys, use addKey as first argument to add ones");
    return;
  }
  window.localStorage.keys.where((String key) => key.endsWith(".key")).forEach((
      String supportingKey) {
    keyNames.add(supportingKey);
    String keyContent = window.localStorage[supportingKey];

    String enc_key = keyContent.split("  ")[0];
    String enc_label = keyContent.split("  ")[1];

    List<Uint8List> toDecrypt = new List();
    enc_label.split(" ").forEach((String s) {
      toDecrypt.add(new Uint8List.fromList(s.codeUnits));
    });

    var params = new KeyParameter(key);
    var ivparams = new ParametersWithIV(params, new Uint8List(16));

    cipher.reset();
    cipher.init(false, ivparams);

    List<String> decrypted = new List();
    for (int i = 0; i < toDecrypt.length; i++) {
      Uint8List decryptedBits = cipher.process(toDecrypt[i]);
      decrypted.add(new String.fromCharCodes(decryptedBits));
      params = new KeyParameter(decryptedBits);
      ivparams = new ParametersWithIV(params, new Uint8List(16));
      cipher.reset();
      cipher.init(false, ivparams);
    }

    labels.add(decrypted.join().replaceAll("-", "").replaceAll("~", "-"));

    toDecrypt = new List();
    enc_key.split(" ").forEach((String s) {
      toDecrypt.add(new Uint8List.fromList(s.codeUnits));
    });

    cipher.reset();
    cipher.init(false, ivparams);

    decrypted = new List();
    for (int i = 0; i < toDecrypt.length; i++) {
      Uint8List decryptedBits = cipher.process(toDecrypt[i]);
      decrypted.add(new String.fromCharCodes(decryptedBits));
      params = new KeyParameter(decryptedBits);
      ivparams = new ParametersWithIV(params, new Uint8List(16));
      cipher.reset();
      cipher.init(false, ivparams);
    }

    generatingKeys.add(decrypted.join().replaceAll("-", ""));
  });

  out.children.clear();

  int now = new DateTime.now().millisecondsSinceEpoch;

  for (int i = 0; i < generatingKeys.length; i++) {
    String pin = OTP.generateTOTPCode(generatingKeys[i], now).toString();
    String label = labels[i];
    String key = keyNames[i];
    out.children.add(new DivElement()..appendHtml("$pin $label from $key"));
  }
}
