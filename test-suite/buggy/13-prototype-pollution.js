// ============================================================================
// TEST SUITE: PROTOTYPE POLLUTION (BUGGY CODE)
// Expected: 18+ CRITICAL issues - Prototype pollution vulnerabilities
// ============================================================================

// BUG 1: Classic prototype pollution via object merge
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key]; // CRITICAL: Can pollute Object.prototype!
  }
  return target;
}
// Attack: merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))

// BUG 2: Recursive merge without prototype checks
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key]; // No __proto__ check
    }
  }
  return target;
}

// BUG 3: Clone function vulnerable to pollution
function clone(obj) {
  const cloned = {};
  for (const key in obj) {
    cloned[key] = obj[key]; // Copies __proto__!
  }
  return cloned;
}

// BUG 4: Setting properties from user input
function setUserPreferences(user, prefs) {
  for (const key in prefs) {
    user[key] = prefs[key]; // User can pollute via __proto__, constructor
  }
}

// BUG 5: Path traversal in object access
function setNestedProperty(obj, path, value) {
  const keys = path.split(".");
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) {
      current[keys[i]] = {};
    }
    current = current[keys[i]]; // No check for __proto__
  }

  current[keys[keys.length - 1]] = value;
}
// Attack: setNestedProperty({}, '__proto__.isAdmin', true)

// BUG 6: Using bracket notation with user input
function updateConfig(config, updates) {
  Object.keys(updates).forEach((key) => {
    config[key] = updates[key]; // Vulnerable to __proto__
  });
}

// BUG 7: Extending objects without validation
function extend(destination, ...sources) {
  sources.forEach((source) => {
    for (const prop in source) {
      destination[prop] = source[prop]; // No hasOwnProperty check
    }
  });
  return destination;
}

// BUG 8: Object.assign with polluted source
function configureApp(userConfig) {
  const config = Object.assign({}, defaultConfig, userConfig);
  // If userConfig has __proto__, it won't pollute via Object.assign
  // BUT manual iteration would:
  for (const key in userConfig) {
    config[key] = userConfig[key]; // VULNERABLE
  }
  return config;
}

// BUG 9: Lodash-style set without sanitization
function set(object, path, value) {
  const keys = Array.isArray(path) ? path : path.split(".");
  let current = object;

  keys.forEach((key, index) => {
    if (index === keys.length - 1) {
      current[key] = value; // No prototype check
    } else {
      current[key] = current[key] || {};
      current = current[key];
    }
  });
}

// BUG 10: Constructor pollution
function createUser(userData) {
  const user = {};
  for (const key in userData) {
    user[key] = userData[key]; // Can pollute constructor.prototype
  }
  return user;
}
// Attack: {"constructor": {"prototype": {"isAdmin": true}}}

// BUG 11: Unsafe property assignment in class
class Config {
  constructor(options) {
    for (const key in options) {
      this[key] = options[key]; // Can pollute class prototype
    }
  }
}

// BUG 12: Parsing and merging JSON without validation
function loadConfig(jsonString) {
  const config = JSON.parse(jsonString);
  const result = {};

  for (const key in config) {
    result[key] = config[key]; // Pollution vector
  }

  return result;
}

// BUG 13: Array.reduce with unsafe accumulator
function mergeAll(objects) {
  return objects.reduce((acc, obj) => {
    for (const key in obj) {
      acc[key] = obj[key]; // Each merge is vulnerable
    }
    return acc;
  }, {});
}

// BUG 14: Spread operator misuse
function combineSettings(...settings) {
  const combined = {};
  settings.forEach((setting) => {
    // Spread is safe, but manual iteration is not:
    for (const prop in setting) {
      combined[prop] = setting[prop]; // VULNERABLE
    }
  });
  return combined;
}

// BUG 15: Default parameter pollution
function processData(data = {}) {
  const result = {};
  Object.keys(data).forEach((key) => {
    result[key] = data[key]; // Seems safe with Object.keys
  });

  // But then:
  for (const key in data) {
    result[key] = data[key]; // VULNERABLE - includes inherited props
  }

  return result;
}

// BUG 16: Unsafe path building
function buildPath(obj, ...keys) {
  return keys.reduce((acc, key) => acc[key], obj);
}
// Can be exploited: buildPath({}, '__proto__', 'isAdmin')

// BUG 17: Polluting via index access
function arrayToObject(arr) {
  const obj = {};
  arr.forEach((val, idx) => {
    obj[idx] = val; // If idx is "__proto__", we have pollution
  });
  return obj;
}

// BUG 18: Vulnerable object factory
function createObject(properties) {
  const obj = Object.create(null); // Starts safe...

  // But then:
  for (const key in properties) {
    obj[key] = properties[key]; // Still vulnerable if Object.create returns null
  }

  return obj;
}

// BUG 19: Middleware pattern pollution
function applyMiddleware(req, res, next) {
  const headers = req.headers;
  for (const header in headers) {
    req[header] = headers[header]; // Can pollute request object
  }
  next();
}

// BUG 20: Template population
function populateTemplate(template, data) {
  const result = { ...template };

  for (const key in data) {
    if (key.includes(".")) {
      // Path traversal vulnerability
      const parts = key.split(".");
      let current = result;
      for (let i = 0; i < parts.length - 1; i++) {
        current[parts[i]] = current[parts[i]] || {};
        current = current[parts[i]];
      }
      current[parts[parts.length - 1]] = data[key];
    } else {
      result[key] = data[key]; // Direct pollution
    }
  }

  return result;
}

// BUG 21: Unsafe defaults pattern
const defaults = {
  timeout: 5000,
  retries: 3,
};

function configure(options) {
  for (const key in options) {
    defaults[key] = options[key]; // Pollutes shared defaults object!
  }
  return defaults;
}

// BUG 22: Cache pollution
const cache = {};

function cacheSet(key, value) {
  cache[key] = value; // If key is __proto__, pollutes all objects
}

function cacheGet(key) {
  return cache[key];
}
