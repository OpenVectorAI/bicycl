/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <string>
#include <sstream>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;

using namespace BICYCL;

/******************************************************************************/
bool check (RandGen &randgen, SecLevel seclevel, size_t niter)
{
  bool success = true;

  std::stringstream desc;
  desc << "security " << seclevel << " bits";

  ECDSA C (seclevel);
  desc << " ECDSA";
  success &= Test::test_sign (C, randgen, niter, desc.str());

  return success;
}

/******************************************************************************/
int
main (int argc, char *argv[])
{
  bool success = true;

  RandGen randgen;
  randseed_from_argv (randgen, argc, argv);

  success &= check (randgen, SecLevel::_112, 50);
  success &= check (randgen, SecLevel::_128, 50);
  success &= check (randgen, SecLevel::_192, 50);
  success &= check (randgen, SecLevel::_256, 50);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
