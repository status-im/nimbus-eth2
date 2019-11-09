import
  strutils, parseutils,
  faststreams/output_stream, json_serialization/writer,
  ../spec/datatypes,
  types, bytes_reader, navigator

export
  navigator

type
  ObjKind = enum
    Record
    Indexable
    LeafValue

  FieldInfo = ref object
    name: string
    fieldType: TypeInfo
    navigator: proc (m: MemRange): MemRange {. gcsafe
                                               noSideEffect
                                               raises: [Defect,
                                                        MalformedSszError] }
  TypeInfo = ref object
    case kind: ObjKind
    of Record:
      fields: seq[FieldInfo]
    of Indexable:
      elemType: TypeInfo
      navigator: proc (m: MemRange, idx: int): MemRange {. gcsafe
                                                           noSideEffect
                                                           raises: [Defect,
                                                                    MalformedSszError] }
    else:
      discard

    jsonPrinter: proc (m: MemRange,
                       outStream: OutputStreamVar,
                       pretty: bool) {.gcsafe, noSideEffect.}

  DynamicSszNavigator* = object
    m: MemRange
    typ: TypeInfo

func jsonPrinterImpl[T](m: MemRange, outStream: OutputStreamVar, pretty: bool) =
  var typedNavigator = sszMount(m, T)
  var jsonWriter = init(JsonWriter, outStream, pretty)
  # TODO: it should be possible to serialize the navigator object
  #       without dereferencing it (to avoid the intermediate value).
  writeValue(jsonWriter, typedNavigator[])

func findField(fields: seq[FieldInfo], name: string): FieldInfo =
  # TODO: Replace this with a binary search?
  #       Will it buy us anything when there are only few fields?
  for field in fields:
    if field.name == name:
      return field

func indexableNavigatorImpl[T](m: MemRange, idx: int): MemRange =
  var typedNavigator = sszMount(m, T)
  getMemRange(typedNavigator[idx])

func fieldNavigatorImpl[RecordType; FieldType;
                        fieldName: static string](m: MemRange): MemRange {.raises: [Defect, MalformedSszError].} =
  # TODO: Make sure this doesn't fail with a Defect when
  #       navigating to an inactive field in a case object.
  var typedNavigator = sszMount(m, RecordType)
  getMemRange navigateToField(typedNavigator, fieldName, FieldType)

func genTypeInfo(T: type): TypeInfo {.gcsafe.}

proc typeInfo*(T: type): TypeInfo =
  let res {.global.} = genTypeInfo(T)

  # TODO This will be safer if the RTTI object use only manually
  #      managed memory, but the `fields` sequence right now make
  #      things harder. We'll need to switch to a different seq type.
  {.gcsafe, noSideEffect.}: res

func genTypeInfo(T: type): TypeInfo =
  mixin toSszType, enumAllSerializedFields
  type SszType = type(toSszType default(T))
  result = when type(SszType) isnot T:
    TypeInfo(kind: LeafValue)
  elif T is object:
    var fields: seq[FieldInfo]
    enumAllSerializedFields(T):
      fields.add FieldInfo(name: fieldName,
                           fieldType: typeInfo(FieldType),
                           navigator: fieldNavigatorImpl[T, FieldType, fieldName])
    TypeInfo(kind: Record, fields: fields)
  elif T is seq|array:
    TypeInfo(kind: Indexable,
             elemType: typeInfo(ElemType(T)),
             navigator: indexableNavigatorImpl[T])
  else:
    TypeInfo(kind: LeafValue)

  result.jsonPrinter = jsonPrinterImpl[T]

func `[]`*(n: DynamicSszNavigator, idx: int): DynamicSszNavigator =
  doAssert n.typ.kind == Indexable
  DynamicSszNavigator(m: n.typ.navigator(n.m, idx), typ: n.typ.elemType)

func navigate*(n: DynamicSszNavigator, path: string): DynamicSszNavigator {.
               raises: [Defect, ValueError, MalformedSszError] .} =
  case n.typ.kind
  of Record:
    let fieldInfo = n.typ.fields.findField(path)
    if fieldInfo == nil:
      raise newException(KeyError, "Unrecogned field name: " & path)
    return DynamicSszNavigator(m: fieldInfo.navigator(n.m),
                               typ: fieldInfo.fieldType)
  of Indexable:
    var idx: int
    let consumed = parseInt(path, idx)
    if consumed == 0 or idx < 0:
      raise newException(KeyError, "Indexing should be done with natural numbers")
    return n[idx]
  else:
    doAssert false, "Navigation should be terminated once you reach a leaf value"

template navigatePathImpl(nav, iterabalePathFragments: untyped) =
  result = nav
  for pathFragment in iterabalePathFragments:
    if pathFragment.len == 0:
      continue
    result = result.navigate(pathFragment)
    if result.typ.kind == LeafValue:
      return

func navigatePath*(n: DynamicSszNavigator, path: string): DynamicSszNavigator {.
                   raises: [Defect, ValueError, MalformedSszError] .} =
  navigatePathImpl n, split(path, '/')

func navigatePath*(n: DynamicSszNavigator, path: openarray[string]): DynamicSszNavigator {.
                   raises: [Defect, ValueError, MalformedSszError] .} =
  navigatePathImpl n, path

func init*(T: type DynamicSszNavigator,
           bytes: openarray[byte], Navigated: type): T =
  T(m: MemRange(startAddr: unsafeAddr bytes[0], length: bytes.len),
    typ: typeInfo(Navigated))

func writeJson*(n: DynamicSszNavigator, outStream: OutputStreamVar, pretty = true) =
  n.typ.jsonPrinter(n.m, outStream, pretty)

func toJson*(n: DynamicSszNavigator, pretty = true): string =
  var outStream = init OutputStream
  writeJson(n, outStream, pretty)
  outStream.getOutput(string)

