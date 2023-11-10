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
#ifndef OPENSSL_WRAPPER_HPP__
#define OPENSSL_WRAPPER_HPP__

#include <stdexcept>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h> /* for NID_* */
#include <openssl/rand.h>

#include "bicycl/gmp_extras.hpp"
#include "bicycl/seclevel.hpp"

namespace BICYCL
{
  namespace OpenSSL
  {
    /*****/
    void random_bytes (unsigned char *buf, int num);

    /*****/
    class HashAlgo
    {
      protected:
        const EVP_MD *md_;
        EVP_MD_CTX *mdctx_;

      public:
        using Digest = std::vector<unsigned char>;

        static const int SHAKE128 = NID_shake128;

        /* constructors */
        HashAlgo (SecLevel seclevel); /* Use SHA3 with desired security level */
        HashAlgo (int nid);

        /* destructor */
        ~HashAlgo ();

        /* getters */
        int digest_size () const;

        template <typename First, typename... Rem>
        Digest operator() (const First &first, const Rem&... rem);

      protected:
        template <typename First, typename... Rem>
        void hash_update (const First & first, const Rem&... rem);

        void hash_update_implem (const void *ptr, size_t n);
    };

    /*****/
    class BN
    {
      friend class ECGroup;

      public:
        BN ();
        BN (const BN &other);
        BN (BN &&other);
        BN & operator= (const BN &other);
        BN & operator= (BN &&other);
        ~BN ();

        /* from Digest */
        explicit BN (const HashAlgo::Digest &digest);
        BN & operator= (const HashAlgo::Digest &digest);

        /* comparisons */
        bool operator== (const BN &other) const;
        bool is_zero () const;

        /* */
        int num_bytes () const;
        static void add (BN &r, const BN&a, const BN &b);

        /* conversion */
        explicit operator const BIGNUM *() const;

      private:
        BIGNUM *bn_;
    }; /* BN */

    /*****/
    template <typename Cryptosystem>
    class ECPoint
    {
      protected:
        EC_POINT *P_;

      public:
        ECPoint (const Cryptosystem &C);
        ECPoint (const Cryptosystem &C, const EC_POINT *Q);
        ~ECPoint ();

        ECPoint & operator= (const EC_POINT *Q);

        friend Cryptosystem;

      protected:
        operator EC_POINT *() const;
    }; /* ECPoint */


    /*****/
    template <typename Cryptosystem>
    class ECKey
    {
      protected:
        EC_KEY *key_;

      public:
        /* constructors */
        ECKey (const Cryptosystem &);

        /* destructor */
        ~ECKey ();

        friend Cryptosystem;

      protected:
        /* conversion */
        operator const BIGNUM *() const;

        /* getters */
        const EC_POINT * get_ec_point () const;
    }; /* ECKey */

    /****/
    class ECGroup
    {
      protected:
        EC_GROUP *ec_group_;
        Mpz order_;
        BN_CTX *ctx_;

      public:
        /* constructors */
        ECGroup (SecLevel seclevel);

        /* destructor */
        ~ECGroup ();

        /* getters */
        const Mpz & order () const;

        /* Wrapper to easily create EC_POINT * and EC_KEY *.
         * Return values must be freed using EC_POINT_free or EC_KEY_free.
         */
        EC_POINT * new_ec_point () const;
        EC_POINT * new_ec_point_copy (const EC_POINT *P) const;
        EC_KEY * new_ec_key () const;

      protected:
        /* utils */
        const EC_POINT * gen () const;
        bool has_correct_order (const EC_POINT *G) const;

        /* arithmetic operations modulo the group order */
        void mod_order (BN &r, const BN &a) const;
        void add_mod_order (BN &r, const BN &a, const BIGNUM *b) const;
        void mul_mod_order (BN &r, const BN &a, const BN &b) const;
        void mul_mod_order (BN &r, const BN &a, const BIGNUM *b) const;
        void inverse_mod_order (BN &r, const BN &a) const;
        void inverse_mod_order (BN &r, const BIGNUM *a) const;
        bool is_positive_less_than_order (const BN &v) const;

        /* elliptic operations */
        bool ec_point_eq (const EC_POINT *P, const EC_POINT *Q) const;
        void get_coords_of_point (BN &x, BN &y, const EC_POINT *P) const;
        void get_x_coord_of_point (BN &x, const EC_POINT *P) const;
        void ec_add (EC_POINT *R, const EC_POINT *P, const EC_POINT *Q) const;
        void scal_mul_gen (EC_POINT *R, const BN &n) const;
        void scal_mul (EC_POINT *R, const BN &n, const EC_POINT *P) const;
        void scal_mul (EC_POINT *R, const BIGNUM *n, const EC_POINT *P) const;
        void scal_mul (EC_POINT *R, const BN &m, const BN &n, const EC_POINT *P) const;

    }; /* ECGroup */

    #include "openssl_wrapper.inl"

  }; /* namespace OpenSSL */

} /* namespace BICYCL */

#endif /* OPENSSL_WRAPPER_HPP__ */
