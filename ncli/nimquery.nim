import
  strutils, strformat, parseutils

type
  TokenKind* = enum
    tIdent          = "ident"
    tNumber         = "number"
    tDot            = "dot"
    tOpenBracket    = "["
    tCloseBracket   = "]"
    tEof            = "end of file"
    tError          = "error"

  Token* = object
    case kind*: TokenKind
    of tIdent:
      name*: string
    of tNumber:
      val*: uint64
    of tError:
      errMsg: string
    else:
      discard

  Lexer* = object
    tok*: Token
    input: string
    pos: int

  Parser* = object
    lexer: Lexer

  NodeKind* = enum
    Ident
    Number
    Dot
    ArrayAccess
    Error

  Node* = ref object
    case kind*: NodeKind
    of Dot:
      objVal*, field*: Node
    of ArrayAccess:
      arrayVal*, index*: Node
    of Ident:
      name*: string
    of Number:
      numVal*: uint64
    of Error:
      errMsg*: string

func advance(lexer: var Lexer) =
  if lexer.pos >= lexer.input.len:
    lexer.tok = Token(kind: tEof)
  else:
    let nextChar = lexer.input[lexer.pos]
    case nextChar
    of IdentStartChars:
      lexer.tok = Token(kind: tIdent)
      lexer.pos = parseIdent(lexer.input, lexer.tok.name, lexer.pos)
    of Whitespace:
      lexer.pos = skipWhitespace(lexer.input, lexer.pos)
      advance lexer
    of Digits:
      lexer.tok = Token(kind: tNumber)
      lexer.pos = parseBiggestUInt(lexer.input, lexer.tok.val, lexer.pos)
    of '[':
      lexer.tok = Token(kind: tOpenBracket)
      inc lexer.pos
    of ']':
      lexer.tok = Token(kind: tCloseBracket)
      inc lexer.pos
    of '.':
      lexer.tok = Token(kind: tDot)
      inc lexer.pos
    else:
      lexer.tok = Token(
        kind: tError,
        errMsg: &"Unexpected character '{nextChar}' at position {lexer.pos}")

func init*(T: type Lexer, src: string): Lexer =
  result.input = src
  result.pos = 0
  advance result

func init*(T: type Parser, src: string): Parser =
  Parser(lexer: Lexer.init(src))

func expr(parser: var Parser): Node =
  template unexpectedToken =
    return Node(kind: Error, errMsg: &"Unexpected {parser.lexer.tok.kind} token")

  case parser.lexer.tok.kind
  of tIdent:
    result = Node(kind: Ident, name: parser.lexer.tok.name)
  of tNumber:
    return Node(kind: Number, numVal: parser.lexer.tok.val)
  else:
    unexpectedToken

  advance parser.lexer
  case parser.lexer.tok.kind
  of tOpenBracket:
    advance parser.lexer
    result = Node(kind: ArrayAccess, arrayVal: result, index: parser.expr)
    if parser.lexer.tok.kind != tCloseBracket:
      unexpectedToken
    else:
      advance parser.lexer
  of tDot:
    advance parser.lexer
    return Node(kind: Dot, objVal: result, field: parser.expr)
  else:
    discard

func parse*(input: string): Node =
  var p = Parser.init(input)
  p.expr

