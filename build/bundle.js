module.exports=function(t){function e(n){if(r[n])return r[n].exports;var i=r[n]={exports:{},id:n,loaded:!1};return t[n].call(i.exports,i,i.exports,e),i.loaded=!0,i.exports}var r={};return e.m=t,e.c=r,e.p="",e(0)}([function(t,e,r){var n=r(10);t.exports=n.fromExpress(r(6))},function(t,e){t.exports=require("boom")},function(t,e,r){(function(t,n){/*!
	 * The buffer module from node.js, for the browser.
	 *
	 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
	 * @license  MIT
	 */
"use strict";function i(){function t(){}try{var e=new Uint8Array(1);return e.foo=function(){return 42},e.constructor=t,42===e.foo()&&e.constructor===t&&"function"==typeof e.subarray&&0===e.subarray(1,1).byteLength}catch(r){return!1}}function o(){return t.TYPED_ARRAY_SUPPORT?2147483647:1073741823}function t(e){return this instanceof t?(t.TYPED_ARRAY_SUPPORT||(this.length=0,this.parent=void 0),"number"==typeof e?s(this,e):"string"==typeof e?a(this,e,arguments.length>1?arguments[1]:"utf8"):u(this,e)):arguments.length>1?new t(e,arguments[1]):new t(e)}function s(e,r){if(e=d(e,0>r?0:0|w(r)),!t.TYPED_ARRAY_SUPPORT)for(var n=0;r>n;n++)e[n]=0;return e}function a(t,e,r){"string"==typeof r&&""!==r||(r="utf8");var n=0|E(e,r);return t=d(t,n),t.write(e,r),t}function u(e,r){if(t.isBuffer(r))return f(e,r);if(K(r))return h(e,r);if(null==r)throw new TypeError("must start with number, buffer, array or string");if("undefined"!=typeof ArrayBuffer){if(r.buffer instanceof ArrayBuffer)return c(e,r);if(r instanceof ArrayBuffer)return l(e,r)}return r.length?p(e,r):g(e,r)}function f(t,e){var r=0|w(e.length);return t=d(t,r),e.copy(t,0,0,r),t}function h(t,e){var r=0|w(e.length);t=d(t,r);for(var n=0;r>n;n+=1)t[n]=255&e[n];return t}function c(t,e){var r=0|w(e.length);t=d(t,r);for(var n=0;r>n;n+=1)t[n]=255&e[n];return t}function l(e,r){return t.TYPED_ARRAY_SUPPORT?(r.byteLength,e=t._augment(new Uint8Array(r))):e=c(e,new Uint8Array(r)),e}function p(t,e){var r=0|w(e.length);t=d(t,r);for(var n=0;r>n;n+=1)t[n]=255&e[n];return t}function g(t,e){var r,n=0;"Buffer"===e.type&&K(e.data)&&(r=e.data,n=0|w(r.length)),t=d(t,n);for(var i=0;n>i;i+=1)t[i]=255&r[i];return t}function d(e,r){t.TYPED_ARRAY_SUPPORT?(e=t._augment(new Uint8Array(r)),e.__proto__=t.prototype):(e.length=r,e._isBuffer=!0);var n=0!==r&&r<=t.poolSize>>>1;return n&&(e.parent=Z),e}function w(t){if(t>=o())throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+o().toString(16)+" bytes");return 0|t}function y(e,r){if(!(this instanceof y))return new y(e,r);var n=new t(e,r);return delete n.parent,n}function E(t,e){"string"!=typeof t&&(t=""+t);var r=t.length;if(0===r)return 0;for(var n=!1;;)switch(e){case"ascii":case"binary":case"raw":case"raws":return r;case"utf8":case"utf-8":return J(t).length;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return 2*r;case"hex":return r>>>1;case"base64":return G(t).length;default:if(n)return J(t).length;e=(""+e).toLowerCase(),n=!0}}function v(t,e,r){var n=!1;if(e=0|e,r=void 0===r||r===1/0?this.length:0|r,t||(t="utf8"),0>e&&(e=0),r>this.length&&(r=this.length),e>=r)return"";for(;;)switch(t){case"hex":return P(this,e,r);case"utf8":case"utf-8":return B(this,e,r);case"ascii":return T(this,e,r);case"binary":return x(this,e,r);case"base64":return U(this,e,r);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return L(this,e,r);default:if(n)throw new TypeError("Unknown encoding: "+t);t=(t+"").toLowerCase(),n=!0}}function m(t,e,r,n){r=Number(r)||0;var i=t.length-r;n?(n=Number(n),n>i&&(n=i)):n=i;var o=e.length;if(o%2!==0)throw new Error("Invalid hex string");n>o/2&&(n=o/2);for(var s=0;n>s;s++){var a=parseInt(e.substr(2*s,2),16);if(isNaN(a))throw new Error("Invalid hex string");t[r+s]=a}return s}function I(t,e,r,n){return z(J(e,t.length-r),t,r,n)}function b(t,e,r,n){return z(X(e),t,r,n)}function R(t,e,r,n){return b(t,e,r,n)}function A(t,e,r,n){return z(G(e),t,r,n)}function _(t,e,r,n){return z(V(e,t.length-r),t,r,n)}function U(t,e,r){return 0===e&&r===t.length?H.fromByteArray(t):H.fromByteArray(t.slice(e,r))}function B(t,e,r){r=Math.min(t.length,r);for(var n=[],i=e;r>i;){var o=t[i],s=null,a=o>239?4:o>223?3:o>191?2:1;if(r>=i+a){var u,f,h,c;switch(a){case 1:128>o&&(s=o);break;case 2:u=t[i+1],128===(192&u)&&(c=(31&o)<<6|63&u,c>127&&(s=c));break;case 3:u=t[i+1],f=t[i+2],128===(192&u)&&128===(192&f)&&(c=(15&o)<<12|(63&u)<<6|63&f,c>2047&&(55296>c||c>57343)&&(s=c));break;case 4:u=t[i+1],f=t[i+2],h=t[i+3],128===(192&u)&&128===(192&f)&&128===(192&h)&&(c=(15&o)<<18|(63&u)<<12|(63&f)<<6|63&h,c>65535&&1114112>c&&(s=c))}}null===s?(s=65533,a=1):s>65535&&(s-=65536,n.push(s>>>10&1023|55296),s=56320|1023&s),n.push(s),i+=a}return S(n)}function S(t){var e=t.length;if(Q>=e)return String.fromCharCode.apply(String,t);for(var r="",n=0;e>n;)r+=String.fromCharCode.apply(String,t.slice(n,n+=Q));return r}function T(t,e,r){var n="";r=Math.min(t.length,r);for(var i=e;r>i;i++)n+=String.fromCharCode(127&t[i]);return n}function x(t,e,r){var n="";r=Math.min(t.length,r);for(var i=e;r>i;i++)n+=String.fromCharCode(t[i]);return n}function P(t,e,r){var n=t.length;(!e||0>e)&&(e=0),(!r||0>r||r>n)&&(r=n);for(var i="",o=e;r>o;o++)i+=N(t[o]);return i}function L(t,e,r){for(var n=t.slice(e,r),i="",o=0;o<n.length;o+=2)i+=String.fromCharCode(n[o]+256*n[o+1]);return i}function O(t,e,r){if(t%1!==0||0>t)throw new RangeError("offset is not uint");if(t+e>r)throw new RangeError("Trying to access beyond buffer length")}function Y(e,r,n,i,o,s){if(!t.isBuffer(e))throw new TypeError("buffer must be a Buffer instance");if(r>o||s>r)throw new RangeError("value is out of bounds");if(n+i>e.length)throw new RangeError("index out of range")}function C(t,e,r,n){0>e&&(e=65535+e+1);for(var i=0,o=Math.min(t.length-r,2);o>i;i++)t[r+i]=(e&255<<8*(n?i:1-i))>>>8*(n?i:1-i)}function D(t,e,r,n){0>e&&(e=4294967295+e+1);for(var i=0,o=Math.min(t.length-r,4);o>i;i++)t[r+i]=e>>>8*(n?i:3-i)&255}function k(t,e,r,n,i,o){if(e>i||o>e)throw new RangeError("value is out of bounds");if(r+n>t.length)throw new RangeError("index out of range");if(0>r)throw new RangeError("index out of range")}function j(t,e,r,n,i){return i||k(t,e,r,4,3.4028234663852886e38,-3.4028234663852886e38),$.write(t,e,r,n,23,4),r+4}function F(t,e,r,n,i){return i||k(t,e,r,8,1.7976931348623157e308,-1.7976931348623157e308),$.write(t,e,r,n,52,8),r+8}function q(t){if(t=M(t).replace(tt,""),t.length<2)return"";for(;t.length%4!==0;)t+="=";return t}function M(t){return t.trim?t.trim():t.replace(/^\s+|\s+$/g,"")}function N(t){return 16>t?"0"+t.toString(16):t.toString(16)}function J(t,e){e=e||1/0;for(var r,n=t.length,i=null,o=[],s=0;n>s;s++){if(r=t.charCodeAt(s),r>55295&&57344>r){if(!i){if(r>56319){(e-=3)>-1&&o.push(239,191,189);continue}if(s+1===n){(e-=3)>-1&&o.push(239,191,189);continue}i=r;continue}if(56320>r){(e-=3)>-1&&o.push(239,191,189),i=r;continue}r=(i-55296<<10|r-56320)+65536}else i&&(e-=3)>-1&&o.push(239,191,189);if(i=null,128>r){if((e-=1)<0)break;o.push(r)}else if(2048>r){if((e-=2)<0)break;o.push(r>>6|192,63&r|128)}else if(65536>r){if((e-=3)<0)break;o.push(r>>12|224,r>>6&63|128,63&r|128)}else{if(!(1114112>r))throw new Error("Invalid code point");if((e-=4)<0)break;o.push(r>>18|240,r>>12&63|128,r>>6&63|128,63&r|128)}}return o}function X(t){for(var e=[],r=0;r<t.length;r++)e.push(255&t.charCodeAt(r));return e}function V(t,e){for(var r,n,i,o=[],s=0;s<t.length&&!((e-=2)<0);s++)r=t.charCodeAt(s),n=r>>8,i=r%256,o.push(i),o.push(n);return o}function G(t){return H.toByteArray(q(t))}function z(t,e,r,n){for(var i=0;n>i&&!(i+r>=e.length||i>=t.length);i++)e[i+r]=t[i];return i}var H=r(11),$=r(14),K=r(15);e.Buffer=t,e.SlowBuffer=y,e.INSPECT_MAX_BYTES=50,t.poolSize=8192;var Z={};t.TYPED_ARRAY_SUPPORT=void 0!==n.TYPED_ARRAY_SUPPORT?n.TYPED_ARRAY_SUPPORT:i(),t.TYPED_ARRAY_SUPPORT?(t.prototype.__proto__=Uint8Array.prototype,t.__proto__=Uint8Array):(t.prototype.length=void 0,t.prototype.parent=void 0),t.isBuffer=function(t){return!(null==t||!t._isBuffer)},t.compare=function(e,r){if(!t.isBuffer(e)||!t.isBuffer(r))throw new TypeError("Arguments must be Buffers");if(e===r)return 0;for(var n=e.length,i=r.length,o=0,s=Math.min(n,i);s>o&&e[o]===r[o];)++o;return o!==s&&(n=e[o],i=r[o]),i>n?-1:n>i?1:0},t.isEncoding=function(t){switch(String(t).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"binary":case"base64":case"raw":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},t.concat=function(e,r){if(!K(e))throw new TypeError("list argument must be an Array of Buffers.");if(0===e.length)return new t(0);var n;if(void 0===r)for(r=0,n=0;n<e.length;n++)r+=e[n].length;var i=new t(r),o=0;for(n=0;n<e.length;n++){var s=e[n];s.copy(i,o),o+=s.length}return i},t.byteLength=E,t.prototype.toString=function(){var t=0|this.length;return 0===t?"":0===arguments.length?B(this,0,t):v.apply(this,arguments)},t.prototype.equals=function(e){if(!t.isBuffer(e))throw new TypeError("Argument must be a Buffer");return this===e?!0:0===t.compare(this,e)},t.prototype.inspect=function(){var t="",r=e.INSPECT_MAX_BYTES;return this.length>0&&(t=this.toString("hex",0,r).match(/.{2}/g).join(" "),this.length>r&&(t+=" ... ")),"<Buffer "+t+">"},t.prototype.compare=function(e){if(!t.isBuffer(e))throw new TypeError("Argument must be a Buffer");return this===e?0:t.compare(this,e)},t.prototype.indexOf=function(e,r){function n(t,e,r){for(var n=-1,i=0;r+i<t.length;i++)if(t[r+i]===e[-1===n?0:i-n]){if(-1===n&&(n=i),i-n+1===e.length)return r+n}else n=-1;return-1}if(r>2147483647?r=2147483647:-2147483648>r&&(r=-2147483648),r>>=0,0===this.length)return-1;if(r>=this.length)return-1;if(0>r&&(r=Math.max(this.length+r,0)),"string"==typeof e)return 0===e.length?-1:String.prototype.indexOf.call(this,e,r);if(t.isBuffer(e))return n(this,e,r);if("number"==typeof e)return t.TYPED_ARRAY_SUPPORT&&"function"===Uint8Array.prototype.indexOf?Uint8Array.prototype.indexOf.call(this,e,r):n(this,[e],r);throw new TypeError("val must be string, number or Buffer")},t.prototype.get=function(t){return console.log(".get() is deprecated. Access using array indexes instead."),this.readUInt8(t)},t.prototype.set=function(t,e){return console.log(".set() is deprecated. Access using array indexes instead."),this.writeUInt8(t,e)},t.prototype.write=function(t,e,r,n){if(void 0===e)n="utf8",r=this.length,e=0;else if(void 0===r&&"string"==typeof e)n=e,r=this.length,e=0;else if(isFinite(e))e=0|e,isFinite(r)?(r=0|r,void 0===n&&(n="utf8")):(n=r,r=void 0);else{var i=n;n=e,e=0|r,r=i}var o=this.length-e;if((void 0===r||r>o)&&(r=o),t.length>0&&(0>r||0>e)||e>this.length)throw new RangeError("attempt to write outside buffer bounds");n||(n="utf8");for(var s=!1;;)switch(n){case"hex":return m(this,t,e,r);case"utf8":case"utf-8":return I(this,t,e,r);case"ascii":return b(this,t,e,r);case"binary":return R(this,t,e,r);case"base64":return A(this,t,e,r);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return _(this,t,e,r);default:if(s)throw new TypeError("Unknown encoding: "+n);n=(""+n).toLowerCase(),s=!0}},t.prototype.toJSON=function(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}};var Q=4096;t.prototype.slice=function(e,r){var n=this.length;e=~~e,r=void 0===r?n:~~r,0>e?(e+=n,0>e&&(e=0)):e>n&&(e=n),0>r?(r+=n,0>r&&(r=0)):r>n&&(r=n),e>r&&(r=e);var i;if(t.TYPED_ARRAY_SUPPORT)i=t._augment(this.subarray(e,r));else{var o=r-e;i=new t(o,void 0);for(var s=0;o>s;s++)i[s]=this[s+e]}return i.length&&(i.parent=this.parent||this),i},t.prototype.readUIntLE=function(t,e,r){t=0|t,e=0|e,r||O(t,e,this.length);for(var n=this[t],i=1,o=0;++o<e&&(i*=256);)n+=this[t+o]*i;return n},t.prototype.readUIntBE=function(t,e,r){t=0|t,e=0|e,r||O(t,e,this.length);for(var n=this[t+--e],i=1;e>0&&(i*=256);)n+=this[t+--e]*i;return n},t.prototype.readUInt8=function(t,e){return e||O(t,1,this.length),this[t]},t.prototype.readUInt16LE=function(t,e){return e||O(t,2,this.length),this[t]|this[t+1]<<8},t.prototype.readUInt16BE=function(t,e){return e||O(t,2,this.length),this[t]<<8|this[t+1]},t.prototype.readUInt32LE=function(t,e){return e||O(t,4,this.length),(this[t]|this[t+1]<<8|this[t+2]<<16)+16777216*this[t+3]},t.prototype.readUInt32BE=function(t,e){return e||O(t,4,this.length),16777216*this[t]+(this[t+1]<<16|this[t+2]<<8|this[t+3])},t.prototype.readIntLE=function(t,e,r){t=0|t,e=0|e,r||O(t,e,this.length);for(var n=this[t],i=1,o=0;++o<e&&(i*=256);)n+=this[t+o]*i;return i*=128,n>=i&&(n-=Math.pow(2,8*e)),n},t.prototype.readIntBE=function(t,e,r){t=0|t,e=0|e,r||O(t,e,this.length);for(var n=e,i=1,o=this[t+--n];n>0&&(i*=256);)o+=this[t+--n]*i;return i*=128,o>=i&&(o-=Math.pow(2,8*e)),o},t.prototype.readInt8=function(t,e){return e||O(t,1,this.length),128&this[t]?-1*(255-this[t]+1):this[t]},t.prototype.readInt16LE=function(t,e){e||O(t,2,this.length);var r=this[t]|this[t+1]<<8;return 32768&r?4294901760|r:r},t.prototype.readInt16BE=function(t,e){e||O(t,2,this.length);var r=this[t+1]|this[t]<<8;return 32768&r?4294901760|r:r},t.prototype.readInt32LE=function(t,e){return e||O(t,4,this.length),this[t]|this[t+1]<<8|this[t+2]<<16|this[t+3]<<24},t.prototype.readInt32BE=function(t,e){return e||O(t,4,this.length),this[t]<<24|this[t+1]<<16|this[t+2]<<8|this[t+3]},t.prototype.readFloatLE=function(t,e){return e||O(t,4,this.length),$.read(this,t,!0,23,4)},t.prototype.readFloatBE=function(t,e){return e||O(t,4,this.length),$.read(this,t,!1,23,4)},t.prototype.readDoubleLE=function(t,e){return e||O(t,8,this.length),$.read(this,t,!0,52,8)},t.prototype.readDoubleBE=function(t,e){return e||O(t,8,this.length),$.read(this,t,!1,52,8)},t.prototype.writeUIntLE=function(t,e,r,n){t=+t,e=0|e,r=0|r,n||Y(this,t,e,r,Math.pow(2,8*r),0);var i=1,o=0;for(this[e]=255&t;++o<r&&(i*=256);)this[e+o]=t/i&255;return e+r},t.prototype.writeUIntBE=function(t,e,r,n){t=+t,e=0|e,r=0|r,n||Y(this,t,e,r,Math.pow(2,8*r),0);var i=r-1,o=1;for(this[e+i]=255&t;--i>=0&&(o*=256);)this[e+i]=t/o&255;return e+r},t.prototype.writeUInt8=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,1,255,0),t.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),this[r]=255&e,r+1},t.prototype.writeUInt16LE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,2,65535,0),t.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8):C(this,e,r,!0),r+2},t.prototype.writeUInt16BE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,2,65535,0),t.TYPED_ARRAY_SUPPORT?(this[r]=e>>>8,this[r+1]=255&e):C(this,e,r,!1),r+2},t.prototype.writeUInt32LE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,4,4294967295,0),t.TYPED_ARRAY_SUPPORT?(this[r+3]=e>>>24,this[r+2]=e>>>16,this[r+1]=e>>>8,this[r]=255&e):D(this,e,r,!0),r+4},t.prototype.writeUInt32BE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,4,4294967295,0),t.TYPED_ARRAY_SUPPORT?(this[r]=e>>>24,this[r+1]=e>>>16,this[r+2]=e>>>8,this[r+3]=255&e):D(this,e,r,!1),r+4},t.prototype.writeIntLE=function(t,e,r,n){if(t=+t,e=0|e,!n){var i=Math.pow(2,8*r-1);Y(this,t,e,r,i-1,-i)}var o=0,s=1,a=0>t?1:0;for(this[e]=255&t;++o<r&&(s*=256);)this[e+o]=(t/s>>0)-a&255;return e+r},t.prototype.writeIntBE=function(t,e,r,n){if(t=+t,e=0|e,!n){var i=Math.pow(2,8*r-1);Y(this,t,e,r,i-1,-i)}var o=r-1,s=1,a=0>t?1:0;for(this[e+o]=255&t;--o>=0&&(s*=256);)this[e+o]=(t/s>>0)-a&255;return e+r},t.prototype.writeInt8=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,1,127,-128),t.TYPED_ARRAY_SUPPORT||(e=Math.floor(e)),0>e&&(e=255+e+1),this[r]=255&e,r+1},t.prototype.writeInt16LE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,2,32767,-32768),t.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8):C(this,e,r,!0),r+2},t.prototype.writeInt16BE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,2,32767,-32768),t.TYPED_ARRAY_SUPPORT?(this[r]=e>>>8,this[r+1]=255&e):C(this,e,r,!1),r+2},t.prototype.writeInt32LE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,4,2147483647,-2147483648),t.TYPED_ARRAY_SUPPORT?(this[r]=255&e,this[r+1]=e>>>8,this[r+2]=e>>>16,this[r+3]=e>>>24):D(this,e,r,!0),r+4},t.prototype.writeInt32BE=function(e,r,n){return e=+e,r=0|r,n||Y(this,e,r,4,2147483647,-2147483648),0>e&&(e=4294967295+e+1),t.TYPED_ARRAY_SUPPORT?(this[r]=e>>>24,this[r+1]=e>>>16,this[r+2]=e>>>8,this[r+3]=255&e):D(this,e,r,!1),r+4},t.prototype.writeFloatLE=function(t,e,r){return j(this,t,e,!0,r)},t.prototype.writeFloatBE=function(t,e,r){return j(this,t,e,!1,r)},t.prototype.writeDoubleLE=function(t,e,r){return F(this,t,e,!0,r)},t.prototype.writeDoubleBE=function(t,e,r){return F(this,t,e,!1,r)},t.prototype.copy=function(e,r,n,i){if(n||(n=0),i||0===i||(i=this.length),r>=e.length&&(r=e.length),r||(r=0),i>0&&n>i&&(i=n),i===n)return 0;if(0===e.length||0===this.length)return 0;if(0>r)throw new RangeError("targetStart out of bounds");if(0>n||n>=this.length)throw new RangeError("sourceStart out of bounds");if(0>i)throw new RangeError("sourceEnd out of bounds");i>this.length&&(i=this.length),e.length-r<i-n&&(i=e.length-r+n);var o,s=i-n;if(this===e&&r>n&&i>r)for(o=s-1;o>=0;o--)e[o+r]=this[o+n];else if(1e3>s||!t.TYPED_ARRAY_SUPPORT)for(o=0;s>o;o++)e[o+r]=this[o+n];else e._set(this.subarray(n,n+s),r);return s},t.prototype.fill=function(t,e,r){if(t||(t=0),e||(e=0),r||(r=this.length),e>r)throw new RangeError("end < start");if(r!==e&&0!==this.length){if(0>e||e>=this.length)throw new RangeError("start out of bounds");if(0>r||r>this.length)throw new RangeError("end out of bounds");var n;if("number"==typeof t)for(n=e;r>n;n++)this[n]=t;else{var i=J(t.toString()),o=i.length;for(n=e;r>n;n++)this[n]=i[n%o]}return this}},t.prototype.toArrayBuffer=function(){if("undefined"!=typeof Uint8Array){if(t.TYPED_ARRAY_SUPPORT)return new t(this).buffer;for(var e=new Uint8Array(this.length),r=0,n=e.length;n>r;r+=1)e[r]=this[r];return e.buffer}throw new TypeError("Buffer.toArrayBuffer not supported in this browser")};var W=t.prototype;t._augment=function(e){return e.constructor=t,e._isBuffer=!0,e._set=e.set,e.get=W.get,e.set=W.set,e.write=W.write,e.toString=W.toString,e.toLocaleString=W.toString,e.toJSON=W.toJSON,e.equals=W.equals,e.compare=W.compare,e.indexOf=W.indexOf,e.copy=W.copy,e.slice=W.slice,e.readUIntLE=W.readUIntLE,e.readUIntBE=W.readUIntBE,e.readUInt8=W.readUInt8,e.readUInt16LE=W.readUInt16LE,e.readUInt16BE=W.readUInt16BE,e.readUInt32LE=W.readUInt32LE,e.readUInt32BE=W.readUInt32BE,e.readIntLE=W.readIntLE,e.readIntBE=W.readIntBE,e.readInt8=W.readInt8,e.readInt16LE=W.readInt16LE,e.readInt16BE=W.readInt16BE,e.readInt32LE=W.readInt32LE,e.readInt32BE=W.readInt32BE,e.readFloatLE=W.readFloatLE,e.readFloatBE=W.readFloatBE,e.readDoubleLE=W.readDoubleLE,e.readDoubleBE=W.readDoubleBE,e.writeUInt8=W.writeUInt8,e.writeUIntLE=W.writeUIntLE,e.writeUIntBE=W.writeUIntBE,e.writeUInt16LE=W.writeUInt16LE,e.writeUInt16BE=W.writeUInt16BE,e.writeUInt32LE=W.writeUInt32LE,e.writeUInt32BE=W.writeUInt32BE,e.writeIntLE=W.writeIntLE,e.writeIntBE=W.writeIntBE,e.writeInt8=W.writeInt8,e.writeInt16LE=W.writeInt16LE,e.writeInt16BE=W.writeInt16BE,e.writeInt32LE=W.writeInt32LE,e.writeInt32BE=W.writeInt32BE,e.writeFloatLE=W.writeFloatLE,e.writeFloatBE=W.writeFloatBE,e.writeDoubleLE=W.writeDoubleLE,e.writeDoubleBE=W.writeDoubleBE,e.fill=W.fill,e.inspect=W.inspect,e.toArrayBuffer=W.toArrayBuffer,e};var tt=/[^+\/0-9A-Za-z-_]/g}).call(e,r(2).Buffer,function(){return this}())},function(t,e){function r(){f&&s&&(f=!1,s.length?u=s.concat(u):h=-1,u.length&&n())}function n(){if(!f){var t=setTimeout(r);f=!0;for(var e=u.length;e;){for(s=u,u=[];++h<e;)s&&s[h].run();h=-1,e=u.length}s=null,f=!1,clearTimeout(t)}}function i(t,e){this.fun=t,this.array=e}function o(){}var s,a=t.exports={},u=[],f=!1,h=-1;a.nextTick=function(t){var e=new Array(arguments.length-1);if(arguments.length>1)for(var r=1;r<arguments.length;r++)e[r-1]=arguments[r];u.push(new i(t,e)),1!==u.length||f||setTimeout(n,0)},i.prototype.run=function(){this.fun.apply(null,this.array)},a.title="browser",a.browser=!0,a.env={},a.argv=[],a.version="",a.versions={},a.on=o,a.addListener=o,a.once=o,a.off=o,a.removeListener=o,a.removeAllListeners=o,a.emit=o,a.binding=function(t){throw new Error("process.binding is not supported")},a.cwd=function(){return"/"},a.chdir=function(t){throw new Error("process.chdir is not supported")},a.umask=function(){return 0}},function(t,e){t.exports=require("fs")},function(t,e){t.exports=require("request")},function(t,e,r){(function(e,n){var i=r(13),o=r(12),s=i(),a=r(8),u=r(16);r(7).config(),s.use(function(t,r,n){return t.webtaskContext?n():(t.webtaskContext={},t.webtaskContext.secrets={},Object.keys(e.env).forEach(function(r){t.webtaskContext.secrets[r]=e.env[r]}),void n())}),s.use(o.json()),s.get("/",function(t,e){e.header("Content-Type","text/html"),e.status(200).send(a())}),s.post("/exchange",function(t,e){var r=t.body.id_token,i=t.webtaskContext.secrets.FIREBASE_SERVICE_PRIVATE_KEY;console.log(i),console.log(i.replace(/\\[n]/g,"\n"));var o=t.webtaskContext.secrets.AUTH0_CLIENT_SECRET;u.verify(r,new n(o,"base64"),function(r,n){return r?e.json({error:"access_denied",error_description:r.toString()},401):void u.sign({uid:n.sub||n.user_id,sub:t.webtaskContext.secrets.FIREBASE_SERVICE_ACCOUNT_ID},i.replace(/\\[n]/g,"\n"),{audience:"https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",expiresIn:3e3,issuer:t.webtaskContext.secrets.FIREBASE_SERVICE_ACCOUNT_ID,algorithm:"RS256"},function(t){e.json({firebase_token:t})})})}),t.exports=s}).call(e,r(3),r(2).Buffer)},function(t,e,r){(function(e){"use strict";var n=r(4);t.exports={config:function(t){var r=".env",i="utf8",o=!1;t&&(t.silent&&(o=t.silent),t.path&&(r=t.path),t.encoding&&(i=t.encoding));try{var s=this.parse(n.readFileSync(r,{encoding:i}));return Object.keys(s).forEach(function(t){e.env[t]=e.env[t]||s[t]}),s}catch(a){return o||console.error(a),!1}},parse:function(t){var e={};return t.toString().split("\n").forEach(function(t){var r=t.match(/^\s*([\w\.\-]+)\s*=\s*(.*)?\s*$/);if(null!=r){var n=r[1],i=r[2]?r[2]:"",o=i?i.length:0;o>0&&'"'===i.charAt(0)&&'"'===i.charAt(o-1)&&(i=i.replace(/\\n/gm,"\n")),i=i.replace(/(^['"]|['"]$)/g,"").trim(),e[n]=i}}),e}},t.exports.load=t.exports.config}).call(e,r(3))},function(t,e,r){var n=r(9);t.exports=function(t){var e=[],r=t||{};return function(t){e.push('<!DOCTYPE html><html><head><title>My Application</title><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=Edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="description"'+n.attr("content",""+t,!0,!0)+'><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="shortcut icon" href="https://cdn.auth0.com/styleguide/2.0.1/lib/logos/img/favicon.png"><link rel="apple-touch-icon" href="apple-touch-icon.png"><link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/manage/v0.3.973/css/index.min.css"><link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/styleguide/latest/index.css"></head><body class="a0-extension"><div class="container"><div class="row"><section class="content-page current"><div class="col-xs-12"><div id="my-application"><h1>Hello world!</h1></div></div></section></div></div></body></html>')}.call(this,"description"in r?r.description:"undefined"!=typeof description?description:void 0),e.join("")}},function(t,e,r){"use strict";function n(t){return null!=t&&""!==t}function i(t){return(Array.isArray(t)?t.map(i):t&&"object"==typeof t?Object.keys(t).filter(function(e){return t[e]}):[t]).filter(n).join(" ")}e.merge=function o(t,e){if(1===arguments.length){for(var r=t[0],i=1;i<t.length;i++)r=o(r,t[i]);return r}var s=t["class"],a=e["class"];(s||a)&&(s=s||[],a=a||[],Array.isArray(s)||(s=[s]),Array.isArray(a)||(a=[a]),t["class"]=s.concat(a).filter(n));for(var u in e)"class"!=u&&(t[u]=e[u]);return t},e.joinClasses=i,e.cls=function(t,r){for(var n=[],o=0;o<t.length;o++)r&&r[o]?n.push(e.escape(i([t[o]]))):n.push(i(t[o]));var s=i(n);return s.length?' class="'+s+'"':""},e.style=function(t){return t&&"object"==typeof t?Object.keys(t).map(function(e){return e+":"+t[e]}).join(";"):t},e.attr=function(t,r,n,i){return"style"===t&&(r=e.style(r)),"boolean"==typeof r||null==r?r?" "+(i?t:t+'="'+t+'"'):"":0==t.indexOf("data")&&"string"!=typeof r?(-1!==JSON.stringify(r).indexOf("&")&&console.warn("Since Jade 2.0.0, ampersands (`&`) in data attributes will be escaped to `&amp;`"),r&&"function"==typeof r.toISOString&&console.warn("Jade will eliminate the double quotes around dates in ISO form after 2.0.0")," "+t+"='"+JSON.stringify(r).replace(/'/g,"&apos;")+"'"):n?(r&&"function"==typeof r.toISOString&&console.warn("Jade will stringify dates in ISO form after 2.0.0")," "+t+'="'+e.escape(r)+'"'):(r&&"function"==typeof r.toISOString&&console.warn("Jade will stringify dates in ISO form after 2.0.0")," "+t+'="'+r+'"')},e.attrs=function(t,r){var n=[],o=Object.keys(t);if(o.length)for(var s=0;s<o.length;++s){var a=o[s],u=t[a];"class"==a?(u=i(u))&&n.push(" "+a+'="'+u+'"'):n.push(e.attr(a,u,!1,r))}return n.join("")},e.escape=function(t){var e=String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");return e===""+t?t:e},e.rethrow=function s(t,e,n,i){if(!(t instanceof Error))throw t;if(!("undefined"==typeof window&&e||i))throw t.message+=" on line "+n,t;try{i=i||r(4).readFileSync(e,"utf8")}catch(o){s(t,null,n)}var a=3,u=i.split("\n"),f=Math.max(n-a,0),h=Math.min(u.length,n+a),a=u.slice(f,h).map(function(t,e){var r=e+f+1;return(r==n?"  > ":"    ")+r+"| "+t}).join("\n");throw t.path=e,t.message=(e||"Jade")+":"+n+"\n"+a+"\n\n"+t.message,t},e.DebugItem=function(t,e){this.lineno=t,this.filename=e}},function(t,e,r){function n(t){return function(e,r,n){var i=s(r.x_wt.jtn);return r.originalUrl=r.url,r.url=r.url.replace(i,"/"),r.webtaskContext=a(e),t(r,n)}}function i(t){var e;return t.ext("onRequest",function(t,r){var n=s(t.x_wt.jtn);t.setUrl(t.url.replace(n,"/")),t.webtaskContext=e}),function(r,n,i){var o=t._dispatch();e=a(r),o(n,i)}}function o(t){return function(e,r,n){var i=s(r.x_wt.jtn);return r.originalUrl=r.url,r.url=r.url.replace(i,"/"),r.webtaskContext=a(e),t.emit("request",r,n)}}function s(t){var e="^/api/run/[^/]+/",r="(?:[^/?#]*/?)?";return new RegExp(e+(t?r:""))}function a(t){function e(t,e,n){var i=r(1);"function"==typeof e&&(n=e,e={}),n(i.preconditionFailed("Storage is not available in this context"))}function n(e,n,i){var o=r(1),s=r(5);"function"==typeof n&&(i=n,n={}),s({uri:t.secrets.EXT_STORAGE_URL,method:"GET",headers:n.headers||{},qs:{path:e},json:!0},function(t,e,r){return t?i(o.wrap(t,502)):404===e.statusCode&&Object.hasOwnProperty.call(n,"defaultValue")?i(null,n.defaultValue):e.statusCode>=400?i(o.create(e.statusCode,r&&r.message)):void i(null,r)})}function i(t,e,n,i){var o=r(1);"function"==typeof n&&(i=n,n={}),i(o.preconditionFailed("Storage is not available in this context"))}function o(e,n,i,o){var s=r(1),a=r(5);"function"==typeof i&&(o=i,i={}),a({uri:t.secrets.EXT_STORAGE_URL,method:"PUT",headers:i.headers||{},qs:{path:e},body:n},function(t,e,r){return t?o(s.wrap(t,502)):e.statusCode>=400?o(s.create(e.statusCode,r&&r.message)):void o(null)})}return t.read=t.secrets.EXT_STORAGE_URL?n:e,t.write=t.secrets.EXT_STORAGE_URL?o:i,t}e.fromConnect=e.fromExpress=n,e.fromHapi=i,e.fromServer=e.fromRestify=o},function(t,e){t.exports=require("base64-js")},function(t,e){t.exports=require("body-parser")},function(t,e){t.exports=require("express")},function(t,e){t.exports=require("ieee754")},function(t,e){t.exports=require("isarray")},function(t,e){t.exports=require("jsonwebtoken")}]);