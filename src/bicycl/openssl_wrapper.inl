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
#ifndef OPENSSL_WRAPPER_INL__
#define OPENSSL_WRAPPER_INL__

/******************************************************************************/
inline
void random_bytes (unsigned char *buf, int num)
{
  int ret = RAND_bytes (buf, num);
  if (ret != 1)
    throw std::runtime_error ("RAND_bytes failed in random_bytes");
}

/******************************************************************************/
/* */
inline
HashAlgo::HashAlgo (int nid) : md_(EVP_get_digestbynid (nid))
{
  if (md_ == NULL)
    throw std::runtime_error ("could not allocate EVP from nid in HashAlgo");

  mdctx_ = EVP_MD_CTX_new ();
  if (mdctx_ == NULL)
    throw std::runtime_error ("EVP_MD_CTX_new failed in HashAlgo");
}

/* */
inline
HashAlgo::HashAlgo (SecLevel seclevel) : HashAlgo (seclevel.sha3_openssl_nid())
{
}

/* */
inline
HashAlgo::~HashAlgo ()
{
  EVP_MD_CTX_free (mdctx_);
}

/* */
inline
int HashAlgo::digest_size () const
{
  return EVP_MD_size (md_);
}

/* */
template <typename First, typename... Rem>
inline
HashAlgo::Digest HashAlgo::operator() (const First &first, const Rem&... rem)
{
  int ret = EVP_DigestInit_ex (mdctx_, md_, NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestInit_ex failed in HashAlgo");

  Digest h (digest_size ());
  hash_update (first, rem...);

  ret = EVP_DigestFinal_ex (mdctx_, h.data(), NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestFinal_ex failed in HashAlgo");

  return h;
}

/* */
template <typename First, typename... Rem>
inline
void HashAlgo::hash_update (const First &first, const Rem&... rem)
{
  hash_update (first);
  hash_update (rem...);
}

/* */
inline
void HashAlgo::hash_update_implem (const void *ptr, size_t n)
{
  int ret = EVP_DigestUpdate (mdctx_, ptr, n);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestUpdate failed in hash_update_implem");
}

/* */
template <>
void HashAlgo::hash_update (const std::vector<unsigned char> &m)
{
  hash_update_implem (m.data(), m.size() * sizeof(unsigned char));
}

/* */
template <>
void HashAlgo::hash_update (const Mpz &v)
{
  mpz_srcptr vptr = static_cast<mpz_srcptr> (v);
  hash_update_implem (mpz_limbs_read (vptr), v.nlimbs() * sizeof (mp_limb_t));
}

/******************************************************************************/
/* */
inline
BN::BN () : bn_(BN_new())
{
  if (bn_ == NULL)
    throw std::runtime_error ("could not allocate BIGNUM");
}

/* */
inline
BN::BN (const BN &other) : bn_ (BN_dup (other.bn_))
{
  if (bn_ == NULL)
    throw std::runtime_error ("could not duplicate BIGNUM");
}

/* */
inline
BN::BN (BN &&other) : bn_(other.bn_)
{
  other.bn_ = NULL;
}

/* */
inline
BN & BN::operator= (const BN &other)
{
  const BIGNUM *ret = BN_copy (bn_, other.bn_);
  if (ret == NULL)
    throw std::runtime_error ("could not copy BIGNUM");
  return *this;
}

/* */
inline
BN & BN::operator= (BN &&other)
{
  bn_ = other.bn_;
  other.bn_ = NULL;
  return *this;
}

/* */
inline
BN::~BN ()
{
  BN_free (bn_);
}

/* */
inline
bool BN::operator== (const BN &other) const
{
  return BN_cmp (bn_, other.bn_) == 0;
}

/* */
inline
BN & BN::operator= (const HashAlgo::Digest &digest)
{
  const BIGNUM *ret = BN_bin2bn (digest.data(), digest.size(), bn_);
  if (ret == NULL)
    throw std::runtime_error ("Could not set BIGNUM from binary");
  return *this;
}

/* */
inline
bool BN::is_zero () const
{
  return BN_is_zero (bn_);
}

/* */
inline
int BN::num_bytes () const
{
  return BN_num_bytes (bn_);
}

/* */
inline
void BN::add (BN &r, const BN&a, const BN &b)
{
  int ret = BN_add (r.bn_, a.bn_, b.bn_);
  if (ret != 1)
    throw std::runtime_error ("BN_add failed");
}

/* */
inline
BN::operator const BIGNUM *() const
{
  return bn_;
}

/* */
template <>
void HashAlgo::hash_update (const OpenSSL::BN &v)
{
  std::vector<unsigned char> bin (v.num_bytes ());
  BN_bn2bin (static_cast<const BIGNUM *>(v), bin.data());
  hash_update (bin);
}

/****************************************************************************/
/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::ECPoint (const Cryptosystem &C) : P_(C.new_ec_point())
{
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::ECPoint (const Cryptosystem &C, const EC_POINT *Q)
  : P_(C.new_ec_point_copy (Q))
{
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem> & ECPoint<Cryptosystem>::operator= (const EC_POINT *Q)
{
  int ret = EC_POINT_copy (P_, Q);
  if (ret != 1)
    throw ("EC_POINT_copy failed in ECPoint::operator=");
  return *this;
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::~ECPoint ()
{
  EC_POINT_free (P_);
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::operator EC_POINT * () const
{
  return P_;
}

/******************************************************************************/
/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::ECKey (const Cryptosystem &C)
    : key_ (C.new_ec_key())
{
}

/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::~ECKey ()
{
  EC_KEY_free (key_);
}

/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::operator const BIGNUM *() const
{
  return EC_KEY_get0_private_key (key_);
}

/* */
template <typename Cryptosystem>
inline
const EC_POINT * ECKey<Cryptosystem>::get_ec_point () const
{
  return EC_KEY_get0_public_key (key_);
}

/******************************************************************************/
/* */
inline
ECGroup::ECGroup (SecLevel seclevel) : ctx_ (BN_CTX_new())
{
  int nid = seclevel.elliptic_curve_openssl_nid(); /* openssl curve id */
  ec_group_ = EC_GROUP_new_by_curve_name (nid);
  if (ec_group_ == NULL)
    throw std::runtime_error ("could not allocate elliptic curve");

  if (ctx_ == NULL)
    throw std::runtime_error ("could not allocate BN_CTX");

  order_ = EC_GROUP_get0_order (ec_group_);
}

/* */
inline
ECGroup::~ECGroup ()
{
  EC_GROUP_free (ec_group_);
  BN_CTX_free (ctx_);
}

/* */
inline
const EC_POINT * ECGroup::gen () const
{
  return EC_GROUP_get0_generator (ec_group_);
}

/* */
inline
const Mpz & ECGroup::order () const
{
  return order_;
}

/* */
inline
void ECGroup::get_coords_of_point (BN &x, BN &y, const EC_POINT *P) const
{
  int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, y.bn_, ctx_);
  if (ret != 1)
    throw std::runtime_error ("Could not get x, y coordinates");
}

/* */
inline
void ECGroup::get_x_coord_of_point (BN &x, const EC_POINT *P) const
{
  int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, NULL, ctx_);
  if (ret != 1)
    throw std::runtime_error ("Could not get x coordinate");
}

/* */
inline
bool ECGroup::ec_point_eq (const EC_POINT *P, const EC_POINT *Q) const
{
  return EC_POINT_cmp (ec_group_, P, Q, ctx_) == 0;
}

/* */
inline
void ECGroup::ec_add (EC_POINT *R, const EC_POINT *P, const EC_POINT *Q) const
{
  int ret = EC_POINT_add (ec_group_, R, P, Q, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_add failed in add");
}

/* */
inline
void ECGroup::scal_mul_gen (EC_POINT *R, const BN &n) const
{
  int ret = EC_POINT_mul (ec_group_, R, n.bn_, NULL, NULL, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul_gen");
}

/* */
inline
void ECGroup::scal_mul (EC_POINT *R, const BIGNUM *n, const EC_POINT *P) const
{
  int ret = EC_POINT_mul (ec_group_, R, NULL, P, n, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
}

/* */
inline
void ECGroup::scal_mul (EC_POINT *R, const BN &n, const EC_POINT *P) const
{
  scal_mul (R, static_cast<const BIGNUM *>(n), P);
}

/* */
inline
void ECGroup::scal_mul (EC_POINT *R, const BN &m, const BN &n,
                        const EC_POINT *P) const
{
  int ret = EC_POINT_mul (ec_group_, R, m.bn_, P, n.bn_, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
}

/* We assume that the order is prime (which must be the case for NIST curves) */
inline
bool ECGroup::has_correct_order (const EC_POINT *G) const
{
  if (EC_POINT_is_at_infinity (ec_group_, G))
    return false;

  if (!EC_POINT_is_on_curve (ec_group_, G, ctx_))
    return false;

  EC_POINT *T = EC_POINT_new (ec_group_);
  if (T == NULL)
    throw std::runtime_error ("EC_POINT_new failed in has_correct_order");

  scal_mul (T, EC_GROUP_get0_order (ec_group_), G);
  bool is_gen = EC_POINT_is_at_infinity (ec_group_, T);
  EC_POINT_free (T);
  return is_gen;
}

/* */
inline
EC_POINT * ECGroup::new_ec_point () const
{
  EC_POINT *P = EC_POINT_new (ec_group_);
  if (P == NULL)
    throw ("EC_POINT_new failed in new_ec_point");
  return P;

}

/* */
inline
EC_POINT * ECGroup::new_ec_point_copy (const EC_POINT *P) const
{
  EC_POINT *Q = EC_POINT_dup (P, ec_group_);
  if (Q == NULL)
    throw ("EC_POINT_dup failed in new_ec_point_copy");
  return Q;
}

/* */
inline
EC_KEY * ECGroup::new_ec_key () const
{
  EC_KEY *key = EC_KEY_new();
  if (key == NULL)
    throw std::runtime_error ("could not allocate EC_KEY in new_ec_key");

  int ret = EC_KEY_set_group (key, ec_group_);
  if (ret != 1)
    throw std::runtime_error ("could not set group in new_ec_key");

  ret = EC_KEY_generate_key (key);
  if (ret != 1)
    throw std::runtime_error ("could not generate key in new_ec_key");

  return key;
}

/* */
inline
void ECGroup::mod_order (BN &r, const BN &a) const
{
  int ret = BN_nnmod (r.bn_, a.bn_, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_nnmod failed");
}

/* */
inline
void ECGroup::add_mod_order (BN &r, const BN &a, const BIGNUM *b) const
{
  int ret = BN_mod_add (r.bn_, a.bn_, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_add failed");
}

/* */
inline
void ECGroup::mul_mod_order (BN &r, const BN &a, const BN &b) const
{
  mul_mod_order (r, a, static_cast<const BIGNUM *>(b));
}

/* */
inline
void ECGroup::mul_mod_order (BN &r, const BN &a, const BIGNUM *b) const
{
  int ret = BN_mod_mul (r.bn_, a.bn_, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_mul failed");
}

/* */
inline
void ECGroup::inverse_mod_order (BN &r, const BN &a) const
{
  inverse_mod_order (r, static_cast<const BIGNUM *>(a));
}

/* */
inline
void ECGroup::inverse_mod_order (BN &r, const BIGNUM *a) const
{
  BIGNUM *ret = BN_mod_inverse (r.bn_, a, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret == NULL)
    throw std::runtime_error ("could not inverse modulo order");
}

/* */
inline
bool ECGroup::is_positive_less_than_order (const BN &v) const
{
  const BIGNUM *order = EC_GROUP_get0_order (ec_group_);
  return !BN_is_negative (v.bn_) && !BN_is_zero (v.bn_)
                                 && BN_cmp (v.bn_, order) < 0;
}

#endif /* OPENSSL_WRAPPER_INL__ */
