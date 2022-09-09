
# Table of Contents

1.  [Bellatrix -> Capella (August 2022)](#org5a7261e)
    1.  [Getting stuck](#org835ddfe)
    2.  [Setup and overview](#orgbaf02eb)
    3.  [Spec files (capella.nim)](#org843501a)
    4.  [Fork file (forks.nim)](#org39f67a2)
    5.  [Review](#org6603b1e)
    6.  [Typing](#org50b8842)
    7.  [Duplication](#org7846de1)
        1.  [Duplication should be preferred](#org055837f)
    8.  [Rebase on `unstable`](#org1d98c5f)
    9.  [Tracking compiler errors](#orge9b96e9)
    10. [Ran into a serialization problem with the spec](#orgc07342f)
    11. [Large amount of typing errors](#org2334a4b)
    12. [Polymorphic errors](#orgedb1c82)
    13. [Ambiguous calls](#org2df0fac)
    14. [sizeof(U) !== sizeof(T)](#org883415d)



<a id="org5a7261e"></a>

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


<a id="org835ddfe"></a>

## Getting stuck

If you run into some difficult type or other error that you can&rsquo;t process.
Try to compile a different part of the project using the command:

`./env.sh nim c beacon_chain/foo.nim`


<a id="orgbaf02eb"></a>

## Setup and overview

Started working on adding the relevant part of the spec files to the capella.nim I added
More cleaning up of the spec files


<a id="org843501a"></a>

## Spec files (capella.nim)

Here it was useful to copy from previous spec files rather than the spec itself
mostly because the spec file types can differ slightly
Functions at the bottom of the page were required for later compilation steps
Better to copy them and try to remove later if possible


<a id="org39f67a2"></a>

## Fork file (forks.nim)

Find and duplicate all bellatrix (previous entry) functions and type names
Better to search next and modify in this case, there are many hidden ones


<a id="org6603b1e"></a>

## Review

Found a few places that should be checked later because the previous
specversion had inconsistencies with the previous spec
marked with TODO and left for the end


<a id="org50b8842"></a>

## Typing

Started working on moving some types into helper and rest<sub>types</sub>
Sorted code in datatypes/capella.nim, and Added TODO to cleanup
these parts later when assured I could remove them (I could not),
More helpers work and slowly tracking the compiler errors


<a id="org7846de1"></a>

## Duplication

Duplication starts with finding functions that match your
previous fork name and duplicating them. I found that
quick-search and replace (in selected region) was very
helpful here.

Tried to generalise some functionality but was unable to
easily because of typing errors.


<a id="org055837f"></a>

### Duplication should be preferred

As it prevents errors with previous forks.

Compiler errors tracked me to more duplicates, however these
errors are not always helpful at telling you where the issue
is as the compiler complains a lot about non-matching types.


<a id="org1d98c5f"></a>

## Rebase on `unstable`

which was thankfully easy and required a few easy refactor

Understand the scope is much more spread
Search and replace prev + new fork everywhere


<a id="orge9b96e9"></a>

## Tracking compiler errors

In general these are helpful at this stage and tell you where
to start looking. However,

at this stage it would be more helpful to
start combing through files. I suggest:

-   prepare a list of files containing `complex(prev_fork)` declarations
-   comb those files using a macro for cases one by one

these steps above will likely save you many compiler errors
be sure to TODO tag the ones which differ from spec to spec


<a id="orgc07342f"></a>

## Ran into a serialization problem with the spec

seemed likely there was no spec version present,
but the code was a bit out of date in one part.
There was a better implementation below which
takes the version (in REST) from the JSON body


<a id="org2334a4b"></a>

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


<a id="orgedb1c82"></a>

## Polymorphic errors

Sometimes we don&rsquo;t import the spec files directly, but rather export
them from some other file.

Search `export {previous_fork_name}` and be sure that all of them are
updated with your new fork name.


<a id="org2df0fac"></a>

## Ambiguous calls

I found that some places the spec has new features from the bellatrix
upgrade which need to be modified or in some way made non-ambiguous.

So far in the slow process of migration type ambiguity has been the single
largest slowdown to progress.


<a id="org883415d"></a>

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

