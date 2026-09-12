/*
Original Authors: Deepak Kumaraswamy, Kanav Gupta
Modified by: Pengzhi Xing
High-dim extension: Scheme 3 (hierarchical high/low split)
*/
#pragma once

#include <array>
#include <cstddef>
#include <cryptoTools/Common/Defines.h>
#include <memory>
#include <vector>
#include "commons/group_element.h"

using namespace osuCrypto;

template <typename T>
class KeyArray {
public:
    KeyArray() = default;
    explicit KeyArray(T* ptr) : ptr_(ptr, std::default_delete<T[]>()) {}
    KeyArray& operator=(T* ptr) { reset(ptr); return *this; }
    void reset(T* ptr = nullptr) {
        if (!ptr) ptr_.reset(); else ptr_.reset(ptr, std::default_delete<T[]>());
    }
    T* data() noexcept { return ptr_.get(); }
    const T* data() const noexcept { return ptr_.get(); }
    T* get() noexcept { return data(); }
    const T* get() const noexcept { return data(); }
    T& operator[](std::size_t i) { return ptr_.get()[i]; }
    const T& operator[](std::size_t i) const { return ptr_.get()[i]; }
    explicit operator bool() const noexcept { return static_cast<bool>(ptr_); }
    operator T*() const noexcept { return ptr_.get(); }
    bool operator==(std::nullptr_t) const noexcept { return ptr_ == nullptr; }
    bool operator!=(std::nullptr_t) const noexcept { return ptr_ != nullptr; }
private:
    std::shared_ptr<T[]> ptr_;
};

template <typename T>
inline KeyArray<T> makeKeyArray(std::size_t size) {
    KeyArray<T> array;
    if (size > 0) array.reset(new T[size]);
    return array;
}

struct DPFKeyPack{
    int Bin=0,Bout=0,groupSize=0,prefixBits=0,suffixBits=-1,vectorSize=0;
    KeyArray<block> k; KeyArray<GroupElement> g; KeyArray<u8> v;
    std::shared_ptr<GroupElement> random_mask; KeyArray<u8> boolean_mask;
    DPFKeyPack(int Bin,int Bout,int gs,block* k,GroupElement* g,u8* v,GroupElement* rm)
        :Bin(Bin),Bout(Bout),groupSize(gs),k(k),g(g),v(v),random_mask(rm){}
    DPFKeyPack()=default;
};
struct BooleanDPFKeyPack{
    int Bin=0,groupSize=0;
    KeyArray<block> k,g; KeyArray<u8> v;
    std::shared_ptr<GroupElement> random_mask; KeyArray<u8> boolean_mask;
};
using DPFETKeyPack = DPFKeyPack;
inline void freeDPFKeyPack(DPFKeyPack&k){k.k.reset();k.g.reset();k.v.reset();k.random_mask.reset();k.boolean_mask.reset();k=DPFKeyPack();}
inline void freeDPFETKeyPack(DPFETKeyPack&k){freeDPFKeyPack(k);}
inline void freeBooleanDPFKeyPack(BooleanDPFKeyPack&k){k.k.reset();k.g.reset();k.v.reset();k.random_mask.reset();k.boolean_mask.reset();k=BooleanDPFKeyPack();}

// ---- MIC family ----------------------------------------------------------
struct PublicInterval { uint64_t left,right; };
struct MICKeyPack{ int Bin,Bout; GroupElement rho_share,payload_share,root_payload_cw; DPFKeyPack iDPFKey; };
inline void freeMICKeyPack(MICKeyPack&k){freeDPFKeyPack(k.iDPFKey);}
struct ComparisonKeyPack{ int Bin,Bout; uint64_t threshold=0; MICKeyPack MICKey; };
inline void freeComparisonKeyPack(ComparisonKeyPack&k){freeMICKeyPack(k.MICKey);}
struct MICBooleanKeyPack{ int Bin; GroupElement rho_share; DPFKeyPack iDPFKey; };
inline void freeMICBooleanKeyPack(MICBooleanKeyPack&k){freeDPFKeyPack(k.iDPFKey);k=MICBooleanKeyPack();}
struct ComparisonBitKeyPack{ int Bin; uint64_t threshold=0; MICBooleanKeyPack MICKey; };
inline void freeComparisonBitKeyPack(ComparisonBitKeyPack&k){freeMICBooleanKeyPack(k.MICKey);k=ComparisonBitKeyPack();}

// =========================================================================
//  Batched failure aggregation material
//
// A zero-test with independent public coefficient vectors replaces the old
// Beaver OR tree.  For a nonzero failure bit, each linear test is uniform in
// Z_{2^Bout}; the default number of repetitions gives at least 128 bits of
// false-acceptance soundness.
// =========================================================================
//  Secret-shared OR-tree material
//
//  The final aggregate is evaluated as a balanced Beaver OR tree. All failure
//  bits and the final OR remain additive shares. Online openings are only
//  Beaver masks, never linear tests of the failure vector.
// =========================================================================
struct BatchedORMaterial {
    int dim = 0, Bout = 0, tree_levels = 0, total_nodes = 0;
    std::vector<GroupElement> a, b, c;
};

inline void freeBatchedORMaterial(BatchedORMaterial& material) {
    material.a.clear();
    material.b.clear();
    material.c.clear();
    material = BatchedORMaterial();
}

// =========================================================================
//  Scheme 3: Hierarchical high/low split for high-dim Z_q comparison
//
//  The high/low split is applied to Boolean shares of a 24-bit random mask,
//  never to arithmetic input shares (which would lose carries).  Online opens
//  one packed mask delta and evaluates four shifted prefix boundaries.
// =========================================================================
struct HighDimScheme3KeyPack {
    int dim=0, Bin=0, Bout=0;
    int high_bits=0, low_bits=0;
    std::vector<uint64_t> thresholds;
    std::vector<GroupElement> rho_shares;       // 24-bit arithmetic shares
    std::vector<MICKeyPack> high_prefix_keys;   // h-bit mask prefixes
    std::vector<MICKeyPack> low_prefix_keys;    // b-bit mask prefixes
    // Four equality*low products per coordinate, consumed online.
    std::vector<GroupElement> product_a, product_b, product_c;
    // Secret-shared aggregate failure bit; no final reconstruction.
    BatchedORMaterial or_material;
    // Scheduling metadata remains bound to the preprocessing record.
    bool endpoint_batched = true;
    bool or_batched = true;
};

inline void freeHighDimScheme3KeyPack(HighDimScheme3KeyPack& key) {
    for(auto& k:key.high_prefix_keys) freeMICKeyPack(k);
    for(auto& k:key.low_prefix_keys) freeMICKeyPack(k);
    key.high_prefix_keys.clear(); key.low_prefix_keys.clear();
    key.thresholds.clear();
    key.rho_shares.clear(); key.product_a.clear(); key.product_b.clear();
    key.product_c.clear();
    freeBatchedORMaterial(key.or_material);
    key = HighDimScheme3KeyPack();
}


// Full-depth reference baseline used by the Table XI monolithic
// versus hierarchical ablation. It is not labelled as a 24/0
// high/low split.
struct HighDimMonolithicKeyPack {
    int dim = 0, Bin = 0, Bout = 0;
    std::vector<uint64_t> thresholds;
    std::vector<MICKeyPack> prefix_keys;
    BatchedORMaterial or_material;
    bool or_batched = true;
};

inline void freeHighDimMonolithicKeyPack(HighDimMonolithicKeyPack& key) {
    for (auto& item : key.prefix_keys) freeMICKeyPack(item);
    key.prefix_keys.clear();
    key.thresholds.clear();
    freeBatchedORMaterial(key.or_material);
    key = HighDimMonolithicKeyPack();
}
