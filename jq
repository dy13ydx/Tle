# Any and Test #any #test
```
.[] | select(any(..; type == "string" and test("MDM6Qm90NDE4OTgyODI"; "i")))
```

Means:

> “Iterate over all items in the top-level array or object then go through **every element recursively** inside the current object or array (`..`) and check:  
> **Does _any_ of them match this Regex condition?**”

---
## Breakdown of `any(..; condition)` 

```jq
any(..; type == "string" and test("pattern"; "i"))
```

Means:

> “Go through **every element recursively** inside the current object or array (`..`) and check:  
> **Does _any_ of them match this Regex condition?**”

---
## Function Signature of `any`
```jq
any(input_expression; condition)
```

| Part                            | Meaning                                              |
| ------------------------------- | ---------------------------------------------------- |
| `..`                            | Generate all values recursively (even deeply nested) |
| `type == "string"` or `strings` | Keep only string values                              |
| `test(...)`                     | Match strings against a regex                        |

---
## What `..` really does:

The `..` operator walks through the entire data tree and emits:
- All objects
- All arrays
- All primitive values (strings, numbers, etc.)

Example:

```json
{
  "user": {
    "name": "Eden",
    "tags": ["pentester", "learner"]
  },
  "active": true
}
```

With `..`, you'll get:

```json
{
  "user": {
    "name": "Eden",
    "tags": ["pentester", "learner"]
  }
}
"user"
{
  "name": "Eden",
  "tags": ["pentester", "learner"]
}
"name"
"Eden"
"tags"
["pentester", "learner"]
"pentester"
"learner"
"active"
true
```

So it walks the full structure.

---
## Putting it Together

```jq
any(..; type == "string" and test("MDM6Qm90NDE4OTgyODI"; "i"))
```

> Start from the current object  
> Recursively grab **all values**  
> Keep only strings  
> Check if **any string** matches the pattern

---
## Test It

Try this: `any(..; type == "string" and test("MDM6Qm90"; "i"))`

```jq
{
  "name": "MDM6Qm90NDE4OTgyODI",
  "profile": {
    "bio": "I love testing with jq",
    "id": "xyz123"
  }
}
```

It will return `true`.

---
## Summary

|Symbol|Meaning|
|---|---|
|`..`|Recursively walk the whole JSON structure|
|`;` in `any`|Separates the input expression and filter logic|
|`any(..; ...)`|Test if any deep value matches the condition|

# to-entries #toentries
## The situation
You have something like this JSON:
```json
{
  "WebServer": {
    "Permissions": {
      "Enrollment Permissions": {
        "Enrollment Rights": ["Domain Admins", "Authenticated Users"]
      }
    }
  },
  "UserTemplate": {
    "Permissions": {
      "Enrollment Permissions": {
        "Enrollment Rights": ["Everyone"]
      }
    }
  }
}
```

So `"Certificate Templates"` is an object with keys like `"WebServer"`, `"UserTemplate"`, etc.
Each template is nested **by name** (not in an array).

---
## The problem without `to_entries[]`
If you don’t use `to_entries[]`, you would have to access each cert template manually:
```jq
."Certificate Templates".WebServer.Permissions...
."Certificate Templates".UserTemplate.Permissions...
```

But the keys like `"WebServer"`, `"UserTemplate"` might change every time (depending on the environment), so you **can’t hardcode them**.

You need a way to **loop over all keys and values**, even if you don’t know their names.

---
## What `to_entries[]` does

It **converts** this:

```json
{
  "WebServer": {...},
  "UserTemplate": {...}
}
```

Into this:

```json
[
  { "key": "WebServer", "value": { ... } },
  { "key": "UserTemplate", "value": { ... } }
]
```

Now you can loop like this:

```jq
."Certificate Templates" | to_entries[] | ...
```

You now have `.key` (template name) and `.value` (the full template object).
And you don't need to care what the key names are. It just works.

# Array Slices & Unpacking #slicing #unpacking

## 1. Think of `jq` as a _stream_
- In `jq`, every filter works on a **stream of values**.
- You pass a value to a filter → it outputs one or more values → the next filter sees those values.
So when you write:
``` bash
.data[0:5]
```
This produces **one value**:  
a **mini-array** containing 5 objects.

---
## 2. Why `[0:5].Properties` doesn’t work
If you try:
``` bash
.data[0:5].Properties.displayname
```
You’re saying:
- Take this array of 5 objects
- Directly look for `.Properties.displayname` on the **array itself**
But an **array doesn’t have `.Properties`** — only the _objects inside_ do.  
That’s why it fails.

---
## 3. Why the `| .[]` is needed
So instead, you do:
``` bash
.data[0:5] | .[]
```
This means:
- Step 1: Get the slice `[0:5]` (an array of 5).
- Step 2: “Unpack” that array into a stream of 5 separate objects.
- Step 3: Now each object individually **does** have `.Properties.displayname`.
Then this works:
``` bash
.data[0:5] | .[].Properties.displayname
```

---
## 4. Shortcut if you don’t want the pipe
You can actually avoid the explicit `| .[]` by writing:
``` bash
.data[0:5][] | .Properties.displayname
```
Here `[]` is applied directly after `[0:5]`, so it unpacks the slice immediately.  
This is just a shorter version of the same logic.

---

👉 So the **reason you need the pipe (or the inline `[]`)** is:
- The slice `[0:5]` gives you an **array**.
- Arrays don’t have `.Properties`.
- You must “explode” the array into its elements with `[]` before asking each one about its properties.
