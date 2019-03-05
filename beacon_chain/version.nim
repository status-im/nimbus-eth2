const
  versionMajor* = 0
  versionMinor* = 1
  versionBuild* = 10

template versionAsStr*: string =
  $versionMajor & "." & $versionMinor & "." & $versionBuild

