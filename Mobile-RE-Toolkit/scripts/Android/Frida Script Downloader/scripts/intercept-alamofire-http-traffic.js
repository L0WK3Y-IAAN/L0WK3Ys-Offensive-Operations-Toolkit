/*
 * Frida Script: Intercept Alamofire network traffic
 * Author: Vinay Kumar Rasala (Xplo8E)
 * Organization: XYSec Labs (Appknox)
 * Target Methods: 
 * -[Alamofire.SessionDelegate URLSession:dataTask:didReceiveData:]
 * -[Alamofire.SessionDelegate URLSession:dataTask:didReceiveResponse:completionHandler:] (Optional to hook for reliability)
 * -[Alamofire.SessionDelegate URLSession:task:didCompleteWithError:]
 */

(function() {

 // Safely gets description for an ObjC object, handling potential nulls
 function safeDescription(obj) {
  try {
   if (obj === null || typeof obj !== 'object') {
    return obj ? obj.toString() : "(null)";
   }
   // Check if the object is explicitly NSNull using isKindOfClass if available
   if (obj.isKindOfClass_ && obj.isKindOfClass_(ObjC.classes.NSNull)) {
    return "(NSNull)";
   }
   // Fallback for primitive types or non-ObjC objects
   return obj.toString();
  } catch (e) {
   // Handle cases where toString() might fail
   try {
    return String(obj);
   } catch (strErr) {
    return "(error getting description)";
   }
  }
 }


 // Formats NSDictionary (like headers) into a readable string for HTTP format
 function formatHeadersForHttp(nsDict) {
  if (!nsDict || nsDict.isKindOfClass_(ObjC.classes.NSNull)) {
   return "(No Headers)";
  }
  try {
   const dict = new ObjC.Object(nsDict);
   const count = dict.count();
   if (count === 0) {
    return "(No Headers)";
   }
   let output = "";
   const keys = dict.allKeys();
   for (let i = 0; i < count; i++) {
    const keyObj = keys.objectAtIndex_(i);
    const valueObj = dict.objectForKey_(keyObj);
    const key = safeDescription(keyObj);
    const value = safeDescription(valueObj);
    // Format as Key: Value
    output += `${key}: ${value}\n`;
   }
   return output.trimEnd(); // Remove trailing newline
  } catch (e) {
   return `(Error formatting headers: ${e.message})`;
  }
 }

 // Processes NSData body: tries UTF-8, falls back to hex/redacted
 // Modified for HTTP format output
 function formatBodyForHttp(nsData, context = "Body") {
  if (!nsData || nsData.isKindOfClass_(ObjC.classes.NSNull)) {
   return `(${context}: No Data)`;
  }
  try {
   const data = new ObjC.Object(nsData);
   const length = data.length();
   if (length === 0) {
    return `(${context}: Empty)`;
   }

   // Try decoding as UTF-8
   // NSUTF8StringEncoding = 4
   const nsString = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
   if (nsString !== null) {
    const str = nsString.toString();
    // For response chunks, use preview length
    if (context === "Response Chunk") {
     // Increased length as requested
     const previewLength = 1000000; // Limit preview length (set high)
     const preview = str.substring(0, previewLength);
     const truncated = str.length > previewLength ? '...' : '';
     // Add length info as a comment line at the end
     return `${preview}${truncated}\n# (${context} Length: ${length} bytes, Encoding: UTF-8)`;
    } else {
     // For request body, return the full string if decoded
     return `${str}\n# (${context} Length: ${length} bytes, Encoding: UTF-8)`;
    }
   } else {
    // If UTF-8 fails, indicate binary/unknown
    return `[Binary or Non-UTF8 Data Redacted]\n# (${context} Length: ${length} bytes)`;
   }

  } catch (e) {
   return `(${context}: Error formatting - ${e.message})`;
  }
 }

 // Hexdump Utility - Kept for potential debugging, but not used in primary formatBodyForHttp
 function hexdump(pointer, options) {
  // ... (full hexdump function remains here) ...
  const {
   offset = 0,
    length = 64, // Default length to dump
    header = true,
    ansi = false // Keep false for cleaner logs unless colors are needed
  } = options || {};

  try {
   // Add check for null pointer before reading
   if (pointer.isNull()) {
    return "    (cannot read null pointer)";
   }
   const buf = Memory.readByteArray(pointer.add(offset), length);
   if (!buf) {
    return "    (cannot read memory)";
   }
   const bytes = new Uint8Array(buf);

   let output = "";
   for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, Math.min(i + 16, bytes.length));
    const addr = (offset + i).toString(16).padStart(8, '0');

    // Hex bytes part
    let hexBytes = "";
    for (let j = 0; j < 16; j++) {
     if (j < slice.length) {
      hexBytes += slice[j].toString(16).padStart(2, '0') + " ";
     } else {
      hexBytes += "   "; // Pad spacing
     }
     if (j === 7) { // Add extra space in the middle
      hexBytes += " ";
     }
    }

    // ASCII chars part
    let chars = "";
    for (let j = 0; j < slice.length; j++) {
     const byte = slice[j];
     chars += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
    }

    if (header && i === 0) {
     // Indent header line
     output += `        00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII\n`;
     output += `      ---------------------------------------------------------------------\n`;
    }
    // Indent data lines
    output += ` ${addr}: ${hexBytes}|${chars}\n`;
   }
   // Return already indented string
   return output.trimEnd(); // Remove trailing newline if any
  } catch (e) {
   return `    (error during hexdump: ${e.message})`;
  }
 }


 // --- Main Interception Logic ---
 const TARGET_CLASS = 'Alamofire.SessionDelegate'; // Adjust if necessary
 let DelegateClasses = [];
 if (ObjC.classes[TARGET_CLASS]) {
  DelegateClasses.push(ObjC.classes[TARGET_CLASS]);
 } else {
  // Not an Alamofire app: hook whichever classes implement the URLSession
  // delegate selectors (the app's own delegate and/or Alamofire's). Only
  // look at classes owned by the app bundle - enumerating the whole ObjC
  // runtime realizes system classes like WebKit whose +initialize can
  // crash the process from a Frida worker thread.
  const wantedSigs = ['- URLSession:dataTask:didReceiveData:', '- URLSession:task:didCompleteWithError:'];
  const bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
  const byImage = ObjC.enumerateLoadedClassesSync();
  const candidates = [];
  for (const image in byImage) {
   if (image.indexOf(bundlePath) === 0 || image.indexOf('Alamofire') !== -1) {
    for (const name of byImage[image]) candidates.push(name);
   }
  }
  for (const name of candidates) {
   try {
    const cls = ObjC.classes[name];
    if (wantedSigs.every((s) => !!cls[s])) DelegateClasses.push(cls);
   } catch (e) {}
  }
  if (DelegateClasses.length > 0) {
   console.log(`[*] ${TARGET_CLASS} not found - hooking URLSession delegates: ${DelegateClasses.map((c) => c.$className).join(', ')}`);
  }
 }

 if (DelegateClasses.length === 0) {
  console.error('[!] No class implements the URLSession delegate selectors - falling back to completion-handler hooks only');
 }

 function installDelegateHooks(DelegateClass, TARGET_CLASS) {

 // 1. Intercept didReceiveData (Modified to attempt status code retrieval)
 const didReceiveDataSig = '- URLSession:dataTask:didReceiveData:';
 const didReceiveDataMethod = DelegateClass[didReceiveDataSig];
 if (didReceiveDataMethod) {
  Interceptor.attach(didReceiveDataMethod.implementation, {
   onEnter(args) {
    let taskId; // Define taskId early for error handling
    try {
     // --- Extract Core Objects ---
     // args[0] = self, args[1] = _cmd
     // args[2] = session (NSURLSession *)
     // args[3] = dataTask (NSURLSessionDataTask *)
     // args[4] = data (NSData *)
     const dataTask = new ObjC.Object(args[3]);
     const responseDataChunk = new ObjC.Object(args[4]);
     const request = dataTask.originalRequest() || dataTask.currentRequest(); // Get request from task
     taskId = dataTask.taskIdentifier(); // Assign taskId

     // --- Format Request (Only print once per task? Or always?)
     // For simplicity, printing request details every time data is received.
     // Could be optimized by storing state if needed.
     console.log(`\n====================[HTTP Request - Task ${taskId}]====================`);
     const url = request.URL();
     const method = safeDescription(request.HTTPMethod());
     const path = safeDescription(url ? url.path() : "/");
     const host = safeDescription(url ? url.host() : "(No Host)");

     console.log(`${method} ${path} HTTP/1.1`); // Assume HTTP/1.1 for formatting
     console.log(`Host: ${host}`);
     console.log(formatHeadersForHttp(request.allHTTPHeaderFields())); // Format request headers
     console.log(""); // Blank line before request body
     console.log(formatBodyForHttp(request.HTTPBody(), "Request Body")); // Format request body

     // --- Attempt to Get Response Status and Headers from DataTask ---
     // NOTE: This relies on the task's 'response' property being set when
     //       didReceiveData is called. This might not be true for the
     //       *very first* call, so status/headers might appear as N/A initially.
     //       Hooking didReceiveResponse is the most reliable way to get these early.
     let statusString = "HTTP/1.1 Status: N/A (Response object not available in task yet)"; // Default message
     let responseHeadersString = "(Response Headers not available in task yet)"; // Default message
     const responsePtr = dataTask.response(); // Try to get the response pointer from the task

     if (responsePtr && !responsePtr.isNull()) {
      const response = new ObjC.Object(responsePtr); // Wrap the valid pointer

      // Check if it's an HTTP response
      if (response.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
       const statusCode = response.statusCode(); // Call directly on response
       const statusText = safeDescription(ObjC.classes.NSHTTPURLResponse.localizedStringForStatusCode_(statusCode));
       statusString = `HTTP/1.1 ${statusCode} ${statusText}`; // Format HTTP status line
       responseHeadersString = formatHeadersForHttp(response.allHeaderFields()); // Format response headers
      } else {
       statusString = "Status: N/A (Response was not HTTP)";
       responseHeadersString = "(Response Headers: Not an HTTP Response)";
      }
     } // If responsePtr is null, statusString/responseHeadersString remain N/A

     // --- Format Response (Partial Chunk) ---
     console.log(`\n====================[HTTP Response Chunk - Task ${taskId}]====================`);
     console.log(statusString); // Print status line derived above
     console.log(responseHeadersString); // Print response headers derived above
     console.log(""); // Blank line before response body chunk

     // console.log(`Chunk Length: ${responseDataChunk.length()}`); // Optionally log chunk length explicitly
     console.log(formatBodyForHttp(responseDataChunk, "Response Chunk")); // Format chunk content

     console.log("===================================================================");


    } catch (error) {
     const taskIdStr = taskId !== undefined ? `Task ${taskId}` : 'unknown'; // Use already defined taskId if available
     console.error(`\n====================[ERROR - ${taskIdStr} in didReceiveData]====================`);
     console.error(`[!] Error processing arguments inside onEnter (didReceiveData): ${error.message}`);
     console.error(`  - Stack: ${error.stack}`);
     // Log arguments for debugging if needed
     // try { console.error("  - Args: ", args[0], args[1], args[2], args[3], args[4]); } catch(e){}
     console.log("===================================================================");
    }
   },
   // onLeave(retval) { // Usually not needed for void methods like this
   //     // console.log(`[*] Leaving didReceiveData for Task ${this.taskId}`);
   // }
  });
  console.log(`[*] Attached to ${TARGET_CLASS} ${didReceiveDataSig}`);
 } else {
  console.warn(`[!] Method not found: ${TARGET_CLASS} ${didReceiveDataSig}`);
 }


 // 2. Intercept didCompleteWithError (Remains the same - Reliable final status)
 // -(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error;
 const didCompleteSig = '- URLSession:task:didCompleteWithError:';
 const didCompleteMethod = DelegateClass[didCompleteSig];
 if (didCompleteMethod) {
  Interceptor.attach(didCompleteMethod.implementation, {
   onEnter(args) {
    let taskId;
    let task; // Declare task here for broader scope in catch block
    try {
     // args[0] = self, args[1] = _cmd
     // args[2] = session (NSURLSession *)
     // args[3] = task (NSURLSessionTask *)
     // args[4] = error (NSError *)
     task = new ObjC.Object(args[3]); // NSURLSessionTask
     taskId = task.taskIdentifier();

     // Check error pointer *before* wrapping or accessing properties
     const errorPtr = args[4];
     let errorDescription = null;
     let hasError = false;

     if (errorPtr && !errorPtr.isNull()) {
      hasError = true;
      // Wrap only if pointer is valid
      const errorObj = new ObjC.Object(errorPtr);
      errorDescription = safeDescription(errorObj.localizedDescription());
     } else {
      // Attempt to get more info even if no explicit NSError*
      const responseForErrorCheck = task.response();
      if (responseForErrorCheck && !responseForErrorCheck.isNull()) {
       const responseObj = new ObjC.Object(responseForErrorCheck);
       if (responseObj.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
        const statusCode = responseObj.statusCode();
        if (statusCode >= 400) { // Treat client/server errors as errors contextually
         hasError = true; // Mark as error for logging context
         errorDescription = `HTTP Error ${statusCode}`;
        }
       }
      }
     }

     let statusString = "Status Code: N/A (No response object found or task errored before response)";

     // Get pointer first, check null, then wrap - Only if no *explicit* error occurred earlier
     // Or maybe always try to get status code? Let's try always.
     const responsePtr = task.response(); // Get pointer to the response object

     if (responsePtr && !responsePtr.isNull()) {
      const response = new ObjC.Object(responsePtr); // Wrap the valid pointer

      // Check if it's an HTTP response
      if (response.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
       const statusCode = response.statusCode(); // Call directly on response
       const statusText = safeDescription(ObjC.classes.NSHTTPURLResponse.localizedStringForStatusCode_(statusCode));
       statusString = `Final Status: ${statusCode} ${statusText}`; // More descriptive for final log
      } else {
       statusString = "Final Status: N/A (Response was not HTTP)";
      }
     } // If responsePtr is null, statusString remains N/A

     // Log completion status
     console.log(`\n--- Task ${taskId} Completed ---`);
     // Use the checked error status and description
     if (hasError) {
      // Ensure errorDescription has a fallback
      const errDetail = errorDescription || '(No specific error details provided)';
      console.log(`  Result: Error - ${errDetail}`);
     } else {
      console.log(`  Result: Success`);
     }
     console.log(` ${statusString}`); // Log the final status code string derived above
     console.log(`---------------------------\n`);

    } catch (e) {
     const taskIdStr = taskId !== undefined ? `Task ${taskId}` : (task ? `Task ${task.taskIdentifier()}` : "Unknown Task");
     console.error(`\n====================[ERROR - ${taskIdStr} in didComplete]====================`);
     console.error(`[!] Error processing arguments inside onEnter (didCompleteWithError): ${e.message}`);
     console.error(`  - Stack: ${e.stack}`);
     // Log arguments for debugging if needed
     // try { console.error("  - Args: ", args[0], args[1], args[2], args[3], args[4]); } catch(e){}
     console.log("===================================================================");
    }
   }
   // onLeave(retval) { // Not needed for void method
   // }
  });
  console.log(`[*] Attached to ${TARGET_CLASS} ${didCompleteSig}`);
 } else {
  console.warn(`[!] Method not found: ${TARGET_CLASS} ${didCompleteSig}`);
 }
 } // end installDelegateHooks

 for (const DelegateClass of DelegateClasses) {
  installDelegateHooks(DelegateClass, DelegateClass.$className);
 }

 // 3. Completion-handler style: apps that use
 // -[NSURLSession dataTaskWithRequest:completionHandler:] instead of a
 // delegate never hit the hooks above, so wrap the completion block to
 // log both the request and the response.
 try {
  const dataTaskWithCompletion = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];
  if (dataTaskWithCompletion) {
   Interceptor.attach(dataTaskWithCompletion.implementation, {
    onEnter(args) {
     try {
      const request = new ObjC.Object(args[2]);
      const url = safeDescription(request.URL().absoluteString());
      const method = safeDescription(request.HTTPMethod());
      console.log(`\n>>> [completion] REQUEST ${method} ${url}`);
      const body = request.HTTPBody();
      if (body && !body.isNull()) {
       const len = body.length();
       if (len > 0) {
        const bytes = body.bytes();
        try {
         console.log(`    Body: ${bytes.readUtf8String(len)}`);
        } catch (e) {
         console.log(`    Body (${len} bytes): ${hexdump(bytes)}`);
        }
       }
      }

      const block = new ObjC.Block(args[3]);
      const originalInvoke = block.implementation;
      if (typeof globalThis._wrappedBlocks === "undefined") globalThis._wrappedBlocks = [];
      globalThis._wrappedBlocks.push(block); // keep the trampoline alive
      block.implementation = function (data, response, error) {
       try {
        if (response && !response.isNull()) {
         const resp = new ObjC.Object(response);
         if (resp.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
          console.log(`<<< [completion] RESPONSE ${resp.statusCode()} ${url}`);
         }
        }
        if (data && !data.isNull()) {
         const d = new ObjC.Object(data);
         const len = d.length();
         if (len > 0) {
          try {
           console.log(`    Body: ${d.bytes().readUtf8String(len)}`);
          } catch (e) {
           console.log(`    Body (${len} bytes): ${hexdump(d.bytes())}`);
          }
         }
        }
        if (error && !error.isNull()) {
         const err = new ObjC.Object(error);
         console.log(`    Error: ${safeDescription(err.localizedDescription())}`);
        }
       } catch (e) {
        console.error(`[!] completion response log failed: ${e.message}`);
       }
       return originalInvoke(data, response, error);
      };
     } catch (e) {
      console.error(`[!] completion request hook failed: ${e.message}`);
     }
    }
   });
   console.log('[*] Attached to NSURLSession - dataTaskWithRequest:completionHandler:');
  }
 } catch (e) {
  console.error(`[!] Could not hook completion-handler path: ${e.message}`);
 }

 console.log("[*] Network logging script (delegate + completion-handler hooks) attached. Waiting for activity...");

})();