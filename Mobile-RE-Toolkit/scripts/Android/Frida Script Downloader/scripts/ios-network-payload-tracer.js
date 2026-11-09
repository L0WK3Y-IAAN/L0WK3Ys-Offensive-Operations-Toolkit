'use strict';

/*
 * ios-network-payload-tracer
 *
 * Trace outgoing iOS network payloads before they leave the app process.
 *
 * Hooks:
 * - NSJSONSerialization
 * - NSMutableURLRequest setHTTPBody:
 * - NSMutableURLRequest header setters
 * - NSURLSession dataTaskWithRequest:
 * - NSURLSession uploadTaskWithRequest:fromData:
 * - NSString dataUsingEncoding:
 *
 * Useful for:
 * - iOS CTFs
 * - SSL pinning / proxy detection cases
 * - Dumping JSON body, headers, tokens, keys, flags
 */

console.log('[+] ios-network-payload-tracer loaded');

setImmediate(function() {
 if (!ObjC.available) {
  console.log('[-] Objective-C runtime is not available');
  return;
 }

 const CONFIG = {
  printJsonSerialization: true,
  printStringToData: false,
  printHeaders: true,
  printRequestBody: true,
  printOnlyInterestingStrings: true,

  interestingPatterns: [
   /CTF\{[^}]+\}/i,
   /flag/i,
   /token/i,
   /secret/i,
   /api[_-]?key/i,
   /key/i,
   /bearer/i,
   /authorization/i
  ]
 };

 function isNull(ptrValue) {
  return !ptrValue || ptrValue.isNull();
 }

 function safeObjC(ptrValue) {
  try {
   if (isNull(ptrValue)) return null;
   return new ObjC.Object(ptrValue);
  } catch (_) {
   return null;
  }
 }

 function nsdataToString(dataPtr) {
  try {
   if (isNull(dataPtr)) return null;

   const data = new ObjC.Object(dataPtr);
   const length = Number(data.length());

   if (length === 0) return '';

   const bytes = data.bytes();

   /*
    * Try UTF-8 first.
    * If it fails, fall back to printable ASCII-ish dump.
    */
   try {
    return bytes.readUtf8String(length);
   } catch (_) {
    const raw = bytes.readByteArray(length);
    const u8 = new Uint8Array(raw);

    let out = '';
    for (let i = 0; i < u8.length; i++) {
     const c = u8[i];

     if (c >= 0x20 && c <= 0x7e) {
      out += String.fromCharCode(c);
     } else if (c === 0x0a) {
      out += '\n';
     } else if (c === 0x0d) {
      out += '\r';
     } else if (c === 0x09) {
      out += '\t';
     } else {
      out += '.';
     }
    }

    return out;
   }
  } catch (_) {
   return null;
  }
 }

 function isInteresting(text) {
  if (!text) return false;

  return CONFIG.interestingPatterns.some(function(pattern) {
   return pattern.test(text);
  });
 }

 function extractFlags(text) {
  if (!text) return [];

  const matches = text.match(/CTF\{[^}]+\}/gi);
  return matches || [];
 }

 function printInteresting(text, source) {
  if (!text) return;

  const shouldPrint = !CONFIG.printOnlyInterestingStrings ||
   isInteresting(text);

  if (!shouldPrint) return;

  console.log('\n========== ' + source + ' ==========');
  console.log(text);

  const flags = extractFlags(text);
  flags.forEach(function(flag) {
   console.log('[+] FLAG FOUND:', flag);
  });

  console.log('====================================\n');
 }

 function printRequest(requestPtr, source) {
  try {
   const request = safeObjC(requestPtr);
   if (!request) return;

   console.log('\n========== ' + source + ' ==========');

   try {
    console.log('[URL]', request.URL().absoluteString().toString());
   } catch (_) {}

   try {
    console.log('[Method]', request.HTTPMethod().toString());
   } catch (_) {}

   if (CONFIG.printHeaders) {
    try {
     const headers = request.allHTTPHeaderFields();
     if (headers && !headers.isNull()) {
      const headerText = headers.toString();
      console.log('[Headers]', headerText);
      printInteresting(headerText, source + ' headers');
     }
    } catch (_) {}
   }

   if (CONFIG.printRequestBody) {
    try {
     const body = request.HTTPBody();

     if (body && !body.isNull()) {
      const bodyText = nsdataToString(body);
      console.log('[Body]', bodyText);
      printInteresting(bodyText, source + ' body');
     } else {
      console.log('[Body] nil');
     }
    } catch (_) {}
   }

   console.log('====================================\n');
  } catch (e) {
   console.log('[-] printRequest failed:', e);
  }
 }

 /*
  * Hook NSJSONSerialization
  *
  * Catches JSON payloads before they are assigned to HTTPBody.
  */
 try {
  const method = ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    if (!CONFIG.printJsonSerialization) return;

    try {
     const obj = safeObjC(args[2]);
     if (!obj) return;

     const text = obj.toString();
     printInteresting(text, 'NSJSONSerialization object');
    } catch (_) {}
   },

   onLeave(retval) {
    if (!CONFIG.printJsonSerialization) return;

    try {
     const jsonText = nsdataToString(retval);
     printInteresting(jsonText, 'NSJSONSerialization data');
    } catch (_) {}
   }
  });

  console.log('[+] Hooked NSJSONSerialization +dataWithJSONObject:options:error:');
 } catch (e) {
  console.log('[-] Failed to hook NSJSONSerialization:', e);
 }

 /*
  * Hook NSMutableURLRequest setHTTPBody:
  *
  * Catches NSData assigned as HTTP body.
  */
 try {
  const method = ObjC.classes.NSMutableURLRequest['- setHTTPBody:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    try {
     const request = safeObjC(args[0]);
     const bodyText = nsdataToString(args[2]);

     console.log('\n========== NSMutableURLRequest setHTTPBody ==========');

     if (request) {
      try {
       console.log('[URL]', request.URL().absoluteString().toString());
      } catch (_) {}

      try {
       console.log('[Method]', request.HTTPMethod().toString());
      } catch (_) {}
     }

     console.log('[Body]', bodyText);
     printInteresting(bodyText, 'setHTTPBody body');

     console.log('=====================================================\n');
    } catch (_) {}
   }
  });

  console.log('[+] Hooked NSMutableURLRequest -setHTTPBody:');
 } catch (e) {
  console.log('[-] Failed to hook NSMutableURLRequest setHTTPBody:', e);
 }

 /*
  * Hook NSMutableURLRequest header setters
  *
  * Catches headers such as Authorization, API keys, tokens.
  */
 [
  '- setValue:forHTTPHeaderField:',
  '- addValue:forHTTPHeaderField:'
 ].forEach(function(selectorName) {
  try {
   const method = ObjC.classes.NSMutableURLRequest[selectorName];

   Interceptor.attach(method.implementation, {
    onEnter(args) {
     if (!CONFIG.printHeaders) return;

     try {
      const valueObj = safeObjC(args[2]);
      const fieldObj = safeObjC(args[3]);

      const value = valueObj ? valueObj.toString() : 'nil';
      const field = fieldObj ? fieldObj.toString() : 'nil';

      const line = field + ': ' + value;

      if (!CONFIG.printOnlyInterestingStrings || isInteresting(line)) {
       console.log('\n========== Header Set ==========');
       console.log('[Selector]', selectorName);
       console.log('[Field]', field);
       console.log('[Value]', value);
       printInteresting(line, 'header');
       console.log('================================\n');
      }
     } catch (_) {}
    }
   });

   console.log('[+] Hooked NSMutableURLRequest ' + selectorName);
  } catch (e) {
   console.log('[-] Failed to hook header setter ' + selectorName + ':', e);
  }
 });

 /*
  * Hook NSURLSession dataTaskWithRequest:
  *
  * Catches the final request before dispatch.
  */
 try {
  const method = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    printRequest(args[2], 'NSURLSession dataTaskWithRequest');
   }
  });

  console.log('[+] Hooked NSURLSession -dataTaskWithRequest:completionHandler:');
 } catch (e) {
  console.log('[-] Failed to hook NSURLSession dataTaskWithRequest:', e);
 }

 /*
  * Hook NSURLSession uploadTaskWithRequest:fromData:
  *
  * Some POST/PUT requests use uploadTask instead of HTTPBody.
  */
 try {
  const method = ObjC.classes.NSURLSession['- uploadTaskWithRequest:fromData:completionHandler:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    printRequest(args[2], 'NSURLSession uploadTaskWithRequest');

    try {
     const uploadBody = nsdataToString(args[3]);

     console.log('\n========== NSURLSession upload body ==========');
     console.log(uploadBody);
     printInteresting(uploadBody, 'uploadTask fromData body');
     console.log('=============================================\n');
    } catch (_) {}
   }
  });

  console.log('[+] Hooked NSURLSession -uploadTaskWithRequest:fromData:completionHandler:');
 } catch (e) {
  console.log('[-] Failed to hook NSURLSession uploadTaskWithRequest:', e);
 }

 /*
  * Hook NSString dataUsingEncoding:
  *
  * Optional noisy hook. Useful when payload is built as NSString first.
  */
 try {
  const method = ObjC.classes.NSString['- dataUsingEncoding:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    if (!CONFIG.printStringToData) return;

    try {
     const strObj = safeObjC(args[0]);
     if (!strObj) return;

     const text = strObj.toString();
     printInteresting(text, 'NSString dataUsingEncoding input');
    } catch (_) {}
   },

   onLeave(retval) {
    if (!CONFIG.printStringToData) return;

    try {
     const text = nsdataToString(retval);
     printInteresting(text, 'NSString dataUsingEncoding output');
    } catch (_) {}
   }
  });

  console.log('[+] Hooked NSString -dataUsingEncoding:');
 } catch (e) {
  console.log('[-] Failed to hook NSString dataUsingEncoding:', e);
 }

 /*
  * Hook legacy NSURLConnection
  */
 try {
  const method = ObjC.classes.NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];

  Interceptor.attach(method.implementation, {
   onEnter(args) {
    printRequest(args[2], 'NSURLConnection sendSynchronousRequest');
   }
  });

  console.log('[+] Hooked NSURLConnection +sendSynchronousRequest:returningResponse:error:');
 } catch (e) {
  console.log('[-] Failed to hook NSURLConnection:', e);
 }

 console.log('[+] Hooks installed. Trigger network activity in the app.');
});