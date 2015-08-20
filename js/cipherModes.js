/**
 * Supported cipher modes.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.cipher = forge.cipher || {};

// supported cipher modes
var modes = forge.cipher.modes = forge.cipher.modes || {};

/** Cipher feedback (CFB) **/

modes.cfb = function(options) {
  options = options || {};
  this.name = 'CFB';
  this.cipher = options.cipher;
  this.blockSize = options.blockSize || 16;
  this._ints = this.blockSize / 4;
  this._inBlock = null;
  this._outBlock = new Array(this._ints);
  this._partialBlock = new Array(this._ints);
  this._partialOutput = forge.util.createBuffer();
  this._partialBytes = 0;
};

modes.cfb.prototype.start = function(options) {
  if(!('iv' in options)) {
    throw new Error('Invalid IV parameter.');
  }
  // use IV as first input
  this._iv = transformIV(options.iv);
  this._inBlock = this._iv.slice(0);
  this._partialBytes = 0;
};

modes.cfb.prototype.encrypt = function(input, output, finish) {
  // not enough input to encrypt
  var inputLength = input.length();
  if(inputLength === 0) {
    return true;
  }

  // encrypt block
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // handle full block
  if(this._partialBytes === 0 && inputLength >= this.blockSize) {
    // XOR input with output, write input as output
    for(var i = 0; i < this._ints; ++i) {
      this._inBlock[i] = input.getInt32() ^ this._outBlock[i];
      output.putInt32(this._inBlock[i]);
    }
    return;
  }

  // handle partial block
  var partialBytes = (this.blockSize - inputLength) % this.blockSize;
  if(partialBytes > 0) {
    partialBytes = this.blockSize - partialBytes;
  }

  // XOR input with output, write input as partial output
  this._partialOutput.clear();
  for(var i = 0; i < this._ints; ++i) {
    this._partialBlock[i] = input.getInt32() ^ this._outBlock[i];
    this._partialOutput.putInt32(this._partialBlock[i]);
  }

  if(partialBytes > 0) {
    // block still incomplete, restore input buffer
    input.read -= this.blockSize;
  } else {
    // block complete, update input block
    for(var i = 0; i < this._ints; ++i) {
      this._inBlock[i] = this._partialBlock[i];
    }
  }

  // skip any previous partial bytes
  if(this._partialBytes > 0) {
    this._partialOutput.getBytes(this._partialBytes);
  }

  if(partialBytes > 0 && !finish) {
    output.putBytes(this._partialOutput.getBytes(
      partialBytes - this._partialBytes));
    this._partialBytes = partialBytes;
    return true;
  }

  output.putBytes(this._partialOutput.getBytes(
    inputLength - this._partialBytes));
  this._partialBytes = 0;
};

modes.cfb.prototype.decrypt = function(input, output, finish) {
  // not enough input to decrypt
  var inputLength = input.length();
  if(inputLength === 0) {
    return true;
  }

  // encrypt block (CFB always uses encryption mode)
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // handle full block
  if(this._partialBytes === 0 && inputLength >= this.blockSize) {
    // XOR input with output, write input as output
    for(var i = 0; i < this._ints; ++i) {
      this._inBlock[i] = input.getInt32();
      output.putInt32(this._inBlock[i] ^ this._outBlock[i]);
    }
    return;
  }

  // handle partial block
  var partialBytes = (this.blockSize - inputLength) % this.blockSize;
  if(partialBytes > 0) {
    partialBytes = this.blockSize - partialBytes;
  }

  // XOR input with output, write input as partial output
  this._partialOutput.clear();
  for(var i = 0; i < this._ints; ++i) {
    this._partialBlock[i] = input.getInt32();
    this._partialOutput.putInt32(this._partialBlock[i] ^ this._outBlock[i]);
  }

  if(partialBytes > 0) {
    // block still incomplete, restore input buffer
    input.read -= this.blockSize;
  } else {
    // block complete, update input block
    for(var i = 0; i < this._ints; ++i) {
      this._inBlock[i] = this._partialBlock[i];
    }
  }

  // skip any previous partial bytes
  if(this._partialBytes > 0) {
    this._partialOutput.getBytes(this._partialBytes);
  }

  if(partialBytes > 0 && !finish) {
    output.putBytes(this._partialOutput.getBytes(
      partialBytes - this._partialBytes));
    this._partialBytes = partialBytes;
    return true;
  }

  output.putBytes(this._partialOutput.getBytes(
    inputLength - this._partialBytes));
  this._partialBytes = 0;
};

/** Utility functions */

function transformIV(iv) {
  if(typeof iv === 'string') {
    // convert iv string into byte buffer
    iv = forge.util.createBuffer(iv);
  }

  if(forge.util.isArray(iv) && iv.length > 4) {
    // convert iv byte array into byte buffer
    var tmp = iv;
    iv = forge.util.createBuffer();
    for(var i = 0; i < tmp.length; ++i) {
      iv.putByte(tmp[i]);
    }
  }
  if(!forge.util.isArray(iv)) {
    // convert iv byte buffer into 32-bit integer array
    iv = [iv.getInt32(), iv.getInt32(), iv.getInt32(), iv.getInt32()];
  }

  return iv;
}

function inc32(block) {
  // increment last 32 bits of block only
  block[block.length - 1] = (block[block.length - 1] + 1) & 0xFFFFFFFF;
}

function from64To32(num) {
  // convert 64-bit number to two BE Int32s
  return [(num / 0x100000000) | 0, num & 0xFFFFFFFF];
}


} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'cipherModes';
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    var nodeJS = true;
    define = function(ids, factory) {
      factory(require, module);
    };
  } else {
    // <script>
    if(typeof forge === 'undefined') {
      forge = {};
    }
    return initModule(forge);
  }
}
// AMD
var deps;
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    }).concat(initModule);
    // handle circular dependencies
    forge = forge || {};
    forge.defined = forge.defined || {};
    if(forge.defined[name]) {
      return forge[name];
    }
    forge.defined[name] = true;
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge[name];
  };
};
var tmpDefine = define;
define = function(ids, factory) {
  deps = (typeof ids === 'string') ? factory.slice(2) : ids.slice(2);
  if(nodeJS) {
    delete define;
    return tmpDefine.apply(null, Array.prototype.slice.call(arguments, 0));
  }
  define = tmpDefine;
  return define.apply(null, Array.prototype.slice.call(arguments, 0));
};
define(['require', 'module', './util'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
