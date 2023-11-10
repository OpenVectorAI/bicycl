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
#ifndef EC_HPP__
#define EC_HPP__

#include "bicycl/seclevel.hpp"
#include "bicycl/gmp_extras.hpp"
#include "bicycl/openssl_wrapper.hpp"

namespace BICYCL
{
  /*****/
  class ECDSA : public OpenSSL::ECGroup
  {
    protected:
      mutable OpenSSL::HashAlgo H_;

    public:
      using SecretKey = OpenSSL::ECKey<ECDSA>;
      using PublicKey = OpenSSL::ECPoint<ECDSA>;
      using Message = std::vector<unsigned char>;

      /*** Signature ***/
      class Signature
      {
        protected:
          OpenSSL::BN r_, s_;

        public:
          /* constructors */
          Signature (const ECDSA &C, const SecretKey &sk, const Message &m);

          friend ECDSA;
      };

      /* constructors */
      ECDSA (SecLevel seclevel);

      /* crypto protocol */
      SecretKey keygen () const;
      PublicKey keygen (const SecretKey &sk) const;
      Signature sign (const SecretKey &sk, const Message &m) const;
      bool verif (const Signature &s, const PublicKey &pk, const Message &m) const;

      /* utils */
      Message random_message () const;

    protected:
      void hash_message (OpenSSL::BN &h, const Message &m) const;
  }; /* ECDSA */

  /*****/
  class ECNIZK : public OpenSSL::ECGroup
  {
    protected:
      mutable OpenSSL::HashAlgo H_;

    public:
      using SecretValue = OpenSSL::ECKey<ECNIZK>;
      using PublicValue = OpenSSL::ECPoint<ECNIZK>;

      class Proof
      {
        protected:
          OpenSSL::ECPoint<ECNIZK> R_;
          OpenSSL::BN c_;
          OpenSSL::BN z_;

        public:
          Proof (const ECNIZK &C, const SecretValue &s);

          bool verify (const ECNIZK &C, const PublicValue &Q) const;
      };

      /* constructors */
      ECNIZK (SecLevel seclevel);

      PublicValue public_value_from_secret (const SecretValue &s) const;

      /* crypto protocol */
      Proof noninteractive_proof (const SecretValue &s) const;
      bool noninteractive_verify (const PublicValue &Q,
                                  const Proof &proof) const;

    protected:
      /* utils */
      void hash_for_challenge (OpenSSL::BN &c, const EC_POINT *R,
                                               const EC_POINT *Q) const;

  }; /* ECNIZK */

  #include "ec.inl"

} /* BICYCL namespace */

#endif /* EC_HPP__ */
