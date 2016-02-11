# Babeltrace C API: Doxygen guidelines

Please follow those guidelines when adding documentation or modifying
existing documentation of the Babeltrace C API using Doxygen.


## Syntax

Syntax example for documenting a function:

    /*!
    @brief Sets the boolean raw value of the boolean value object
            \p bool_obj to \p val.

    @param[in] bool_obj     Boolean value object of which to set
                            the raw value
    @param[in] val          New boolean raw value
    @returns                One of #bt_value_status values

    @sa bt_value_bool_get(): Returns the raw value of a given boolean
            value object
    */

Rules:

  * Try to stay behind the 72th column mark if possible, and behind the
    80th column otherwise.
  * Start the block with `@brief` followed by a space followed by the
    brief description. If the brief description needs more than one
    line, start the following lines with a tab character. Try to always
    refer to all function parameters in the brief. The sentence must
    begin with a verb, third-person singular. The brief must contain
    a single sentence ending with a period.
  * When referring to parameters, use the `\p` command.
  * When referring to any keyword/definition, use the `\c` command if
    it's a single word, otherwise surround the words with `<code>` and
    `</code>`.
  * Add a new line before the parameter descriptions.
  * The syntax for a parameter line is: `@param` followed by `[in]`
    (input parameter), `[out]` (output parameter), or `[in,out]`
    (input/output parameter), followed by at least one tab character,
    followed by the description. The parameter description does not end
    with a period. Make sure all the beginnings of the parameter
    descriptions and of the return value description are vertically
    aligned by using as many tabs as required. If more than one line is
    needed, align the beginning of the second line with the beginning of
    the first one (see the return value description in the example
    above).
  * The syntax for the return value line is: `@returns` (not `@return`)
    followed by at least one tab character, followed by the description.
    The description does not end with a period. The description often
    takes the form "X on success, or Y on error".
  * When relevant, add a new line after the return description and put
    as many _see also_ links as needed on the following lines. The
    syntax of those lines is: `@sa` followed by the function/structure
    name, followed by `:`, followed by a space, followed by a brief,
    capitalized description of the target not ending with a period.
  * Prefer the `@` commands to the `\` commands for commands starting
    at the beginning of a line.


## Style convention

The ultimate goal of the Babeltrace C API documentation is to make the
layman write code using this API as fast as possible without having to
ask for help. For this purpose, the documentation should always be as
clear as possible, just like the function and type names try to be.

Do not hesitate to repeat technical terms, even in the same sentence, if
needed. For example, if documenting a _value object_, then always use
the term _value object_ in the documentation, not _value_, nor _object_,
since they are ambiguous.

Light emphasis can signal the importance of a part of the text by using
the `\em` command (one word) or by surrounding the text to emphasize
with `<em>` and `</em>`. Likewise, strong emphasis can be used when
needed using `\b` (one word) or `<strong>`/`</strong>`. In general,
prefer light emphasis to strong emphasis.

Links to other parts of the documentation are very important. Doxygen
will automatically generate most of the links when using the `func()`
syntax to refer to a function or the `file.h` syntax to refer to a file.
However, links to variables need to use the `\ref variable` syntax.
Also, sometimes it is desired to add a link with a text different from
the target. `\link` and `\endlink` can be used if this is the case, for
example:

    It is possible to create an \link event.h event\endlink using [...]
    By calling \link func() said function\endlink, [...]

Except in tutorials and user guides, keep the text as impersonal as
possible, that is, minimize the uses of _I_, _we_, _us_, and so on.

Avoid Latin abbreviations.

Do not use the future tense when it's not necessary (which is almost
always).


### Babeltrace object names

Here are the official names of the Babeltrace objects to be used as is
in the API documentation:

  * Value objects
    * The null value object (_the_, not _a_, since it's a singleton
      variable)
    * Boolean value object
    * Integer value object
    * Floating point number value object
    * String value object
    * Array value object
    * Map value object
  * CTF IR field path object
  * CTF IR field types
    * CTF IR integer field type
    * CTF IR floating point number field type
    * CTF IR enumeration field type
    * CTF IR string field type
    * CTF IR array field type
    * CTF IR sequence field type
    * CTF IR structure field type
    * CTF IR variant field type
  * CTF IR fields
    * CTF IR integer field
    * CTF IR floating point number field
    * CTF IR enumeration field
    * CTF IR string field
    * CTF IR array field
    * CTF IR sequence field
    * CTF IR structure field
    * CTF IR variant field
  * CTF IR event class
  * CTF IR stream class
  * CTF IR trace
  * CTF IR event
  * CTF IR stream
  * CTF IR writer

Note that once _CTF IR_ has been mentioned in an object name, it can be
omitted in the few following paragraphs.
