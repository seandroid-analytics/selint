#!/bin/bash
#
#    Written by Filippo Bonazzi
#    Copyright (C) 2015 Aalto University
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
tmpfile=$(mktemp)
testno=$(git grep -e "\<def test" ./test/ | wc -l)
#echo "Running $testno tests"
python -m unittest discover ./test/ 2>"$tmpfile"
retval=$?
cat "$tmpfile"
actualno=$(grep -oPe '(?<=Ran )[0-9]+(?= test[s]? in)' "$tmpfile")
if [[ -z $actualno || $testno -ne $actualno ]]
then
	>&2 echo "$(($testno-$actualno)) tests present but not recognized!"
	if [[ $retval -eq 0 ]]
	then
		retval=1
	fi
fi

rm "$tmpfile"
exit $retval
