
# Table of Contents

1.  [Bellatrix -> Capella (August 2022)](#orga9cb28e)
    1.  [Setup and overview](#orgb55d43d)
    2.  [Spec files (capella.nim)](#org841fa8d)
    3.  [Fork file (forks.nim)](#org93c364b)
    4.  [Review](#org8a8b0a8)
    5.  [Typing](#org14b11a6)
    6.  [Duplication](#org6c47389)
        1.  [Duplication should be preferred](#org0e7075d)
    7.  [Rebase on `unstable`](#orgda99c04)
    8.  [Tracking compiler errors](#org78596b2)
    9.  [Ran into a serialization problem with the spec](#orge2e15b4)
    10. [Large amount of typing errors](#orge24f293)
    11. [Polymorphic errors](#org625eca5)
    12. [Ambiguous calls](#orgf36c394)
    13. [sizeof(U) !== sizeof(T)](#orgbad8329)



<a id="orga9cb28e"></a>

# Bellatrix -> Capella (August 2022)

In this guide I mostly lay out the problems I ran into
while making the forward migration.

In general I would suggest getting the spec/datatypes/\\\* files
done first and them performing a search-and replace sweep on the
whole project.

Look for all complex matches and then prepare macros for different
files to sweep.

Stop at unviable areas, tag with TODO and get it to compile first.

&#x2014;


<a id="orgb55d43d"></a>

## Setup and overview

Started working on adding the relevant part of the spec files to the capella.nim I added
More cleaning up of the spec files


<a id="org841fa8d"></a>

## Spec files (capella.nim)

Here it was useful to copy from previous spec files rather than the spec itself
mostly because the spec file types can differ slightly
Functions at the bottom of the page were required for later compilation steps
Better to copy them and try to remove later if possible


<a id="org93c364b"></a>

## Fork file (forks.nim)

Find and duplicate all bellatrix (previous entry) functions and type names
Better to search next and modify in this case, there are many hidden ones


<a id="org8a8b0a8"></a>

## Review

Found a few places that should be checked later because the previous
specversion had inconsistencies with the previous spec
marked with TODO and left for the end


<a id="org14b11a6"></a>

## Typing

Started working on moving some types into helper and rest<sub>types</sub>
Sorted code in datatypes/capella.nim, and Added TODO to cleanup
these parts later when assured I could remove them (I could not),
More helpers work and slowly tracking the compiler errors


<a id="org6c47389"></a>

## Duplication

Duplication starts with finding functions that match your
previous fork name and duplicating them. I found that
quick-search and replace (in selected region) was very
helpful here.

Tried to generalise some functionality but was unable to
easily because of typing errors.


<a id="org0e7075d"></a>

### Duplication should be preferred

As it prevents errors with previous forks.

Compiler errors tracked me to more duplicates, however these
errors are not always helpful at telling you where the issue
is as the compiler complains a lot about non-matching types.


<a id="orgda99c04"></a>

## Rebase on `unstable`

which was thankfully easy and required a few easy refactor

Understand the scope is much more spread
Search and replace prev + new fork everywhere


<a id="org78596b2"></a>

## Tracking compiler errors

In general these are helpful at this stage and tell you where
to start looking. However,

at this stage it would be more helpful to
start combing through files. I suggest:

-   prepare a list of files containing `complex(prev_fork)` declarations
-   comb those files using a macro for cases one by one

these steps above will likely save you many compiler errors
be sure to TODO tag the ones which differ from spec to spec


<a id="orge2e15b4"></a>

## Ran into a serialization problem with the spec

seemed likely there was no spec version present,
but the code was a bit out of date in one part.
There was a better implementation below which
takes the version (in REST) from the JSON body


<a id="orge24f293"></a>

## Large amount of typing errors

This was likely because I culled out some
important functions from `capella.nim` too early.

At this point I also ran into `sizeof(U) or sizeof(T)` problems
which was caused because the spec is duplicated in a few places
and also made immutable. All areas must be updated correctly.

More typing problems, this time with `shortLog` who&rsquo;s asking
for a BeaconBlock and getting one, but does not seem happy.
Found some more missed areas from the first code sweep and fixed
them up.


<a id="org625eca5"></a>

## Polymorphic errors

Sometimes we don&rsquo;t import the spec files directly, but rather export
them from some other file.

Search `export {previous_fork_name}` and be sure that all of them are
updated with your new fork name.


<a id="orgf36c394"></a>

## Ambiguous calls

I found that some places the spec has new features from the bellatrix
upgrade which need to be modified or in some way made non-ambiguous.

So far in the slow process of migration type ambiguity has been the single
largest slowdown to progress.


<a id="orgbad8329"></a>

## sizeof(U) !== sizeof(T)

Go into datatypes/base.nim and uncomment the following lines:

    # NOTE: Uncomment for debugging type size mismatch
    echo alignLeft($T.typeof & ":", 50), T.sizeof
    echo alignLeft($U.typeof & ":", 50), U.sizeof, "\n", repeat("-", 20)

Then rebuild. This should print out the typenames and the corresponding
size when an isomorphicCast attempt is made during compile time.
Hopefully this will allow you to narrow down exactly which types are
causing the issue.

Most of these issues are caused by a missing duplicate item in one of your spec
files. It could also be in the file `beacon_chain_db_immutable.nim`

