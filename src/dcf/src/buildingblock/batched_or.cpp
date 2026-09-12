#include "buildingblock/batched_or.h"

#include <stdexcept>
#include <vector>

#include "mpc/api.h"
#include "mpc/secure_ops.h"

namespace dfss {

// Generate exactly dim-1 Beaver triples for a balanced secret-shared OR tree.
BatchedORMaterial batchedOrOffline(int party_id, int dim, int Bout,
                                   bool batched) {
    if (dim <= 0 || Bout <= 0 || Bout > 64) {
        throw std::invalid_argument("batchedOrOffline: invalid dimensions");
    }

    BatchedORMaterial material;
    material.dim = dim;
    material.Bout = Bout;

    int width = dim;
    while (width > 1) {
        material.total_nodes += width / 2;
        width = (width + 1) / 2;
        ++material.tree_levels;
    }

    material.a.resize(material.total_nodes, GroupElement(0, Bout));
    material.b.resize(material.total_nodes, GroupElement(0, Bout));
    material.c.resize(material.total_nodes, GroupElement(0, Bout));

    if (material.total_nodes > 0 && batched) {
        beaver_mult_offline(
            party_id, material.a.data(), material.b.data(),
            material.c.data(), peer, material.total_nodes);
    } else if (material.total_nodes > 0) {
        for (int index = 0; index < material.total_nodes; ++index) {
            beaver_mult_offline(party_id, &material.a[index],
                                &material.b[index], &material.c[index],
                                peer, 1);
        }
    }

    return material;
}

// Compute and return a secret share of OR(input[0], ..., input[d-1]).
//
// For each pair L,R:
//     L OR R = L + R - L*R.
//
// The only opened values are Beaver masks L-a and R-b. No failure bit,
// random linear test, or final aggregate is reconstructed.
GroupElement batchedOrOnline(
    int party_id,
    const GroupElement* input,
    const BatchedORMaterial& material,
    bool batched
) {
    const int dim = material.dim;
    const int Bout = material.Bout;

    if (dim <= 0 || input == nullptr || Bout <= 0 ||
        material.total_nodes != dim - 1 ||
        static_cast<int>(material.a.size()) != material.total_nodes ||
        static_cast<int>(material.b.size()) != material.total_nodes ||
        static_cast<int>(material.c.size()) != material.total_nodes) {
        throw std::invalid_argument("batchedOrOnline: malformed material");
    }

    if (party_id != SERVER && party_id != CLIENT) {
        throw std::invalid_argument("batchedOrOnline: unsupported party");
    }

    std::vector<GroupElement> current(input, input + dim);
    int triple_offset = 0;

    while (current.size() > 1) {
        const int pair_count = static_cast<int>(current.size() / 2);
        const int next_count = static_cast<int>((current.size() + 1) / 2);

        std::vector<GroupElement> opened_masks(
            2 * pair_count, GroupElement(0, Bout));

        for (int index = 0; index < pair_count; ++index) {
            opened_masks[index] =
                current[2 * index] - material.a[triple_offset + index];
            opened_masks[pair_count + index] =
                current[2 * index + 1] - material.b[triple_offset + index];
        }

        // Standard Beaver openings: reconstruct [d || e] together.
        if (batched) {
            reconstruct(2 * pair_count, opened_masks.data(), Bout);
        } else {
            for (int index = 0; index < pair_count; ++index) {
                GroupElement pair[2] = {
                    opened_masks[index], opened_masks[pair_count + index]};
                reconstruct(2, pair, Bout);
                opened_masks[index] = pair[0];
                opened_masks[pair_count + index] = pair[1];
            }
        }

        std::vector<GroupElement> next(
            next_count, GroupElement(0, Bout));

        for (int index = 0; index < pair_count; ++index) {
            const uint64_t d = opened_masks[index].value;
            const uint64_t e = opened_masks[pair_count + index].value;

            const GroupElement product =
                material.c[triple_offset + index] +
                material.b[triple_offset + index] * d +
                material.a[triple_offset + index] * e +
                GroupElement(d * e, Bout) *
                    static_cast<uint64_t>(party_id - SERVER);

            next[index] =
                current[2 * index] +
                current[2 * index + 1] -
                product;
        }

        // Carry the unpaired element upward without opening it.
        if (current.size() % 2 == 1) {
            next.back() = current.back();
        }

        triple_offset += pair_count;
        current.swap(next);
    }

    if (triple_offset != material.total_nodes) {
        throw std::logic_error("batchedOrOnline: triple consumption mismatch");
    }

    return current.front();
}

std::vector<GroupElement> batchedOrOnlineBatch(
    int party_id, const GroupElement* flattened_input,
    const std::vector<const BatchedORMaterial*>& materials,
    bool batched) {
    const int candidates = static_cast<int>(materials.size());
    if (candidates <= 0 || flattened_input == nullptr ||
        (party_id != SERVER && party_id != CLIENT)) {
        throw std::invalid_argument("batchedOrOnlineBatch: invalid argument");
    }
    const int dim = materials[0] ? materials[0]->dim : 0;
    const int Bout = materials[0] ? materials[0]->Bout : 0;
    if (dim <= 0 || Bout <= 0) {
        throw std::invalid_argument("batchedOrOnlineBatch: malformed material");
    }

    std::vector<std::vector<GroupElement>> current(candidates);
    std::vector<int> triple_offsets(candidates, 0);
    for (int candidate = 0; candidate < candidates; ++candidate) {
        const BatchedORMaterial* material = materials[candidate];
        if (material == nullptr || material->dim != dim ||
            material->Bout != Bout || material->total_nodes != dim - 1 ||
            static_cast<int>(material->a.size()) != material->total_nodes ||
            static_cast<int>(material->b.size()) != material->total_nodes ||
            static_cast<int>(material->c.size()) != material->total_nodes) {
            throw std::invalid_argument(
                "batchedOrOnlineBatch: inconsistent material");
        }
        current[candidate].assign(flattened_input + candidate * dim,
                                  flattened_input + (candidate + 1) * dim);
    }

    while (current[0].size() > 1) {
        const int width = static_cast<int>(current[0].size());
        const int pair_count = width / 2;
        const int next_count = (width + 1) / 2;
        const int products = candidates * pair_count;
        std::vector<GroupElement> opened(2 * products,
                                         GroupElement(0, Bout));

        for (int candidate = 0; candidate < candidates; ++candidate) {
            if (static_cast<int>(current[candidate].size()) != width) {
                throw std::logic_error(
                    "batchedOrOnlineBatch: tree width mismatch");
            }
            const BatchedORMaterial& material = *materials[candidate];
            for (int pair_index = 0; pair_index < pair_count; ++pair_index) {
                const int flat = candidate * pair_count + pair_index;
                const int triple = triple_offsets[candidate] + pair_index;
                opened[flat] = current[candidate][2 * pair_index] -
                               material.a[triple];
                opened[products + flat] =
                    current[candidate][2 * pair_index + 1] -
                    material.b[triple];
            }
        }

        if (batched) {
            reconstruct(2 * products, opened.data(), Bout);
        } else {
            for (int flat = 0; flat < products; ++flat) {
                GroupElement pair[2] = {opened[flat], opened[products + flat]};
                reconstruct(2, pair, Bout);
                opened[flat] = pair[0];
                opened[products + flat] = pair[1];
            }
        }

        for (int candidate = 0; candidate < candidates; ++candidate) {
            const BatchedORMaterial& material = *materials[candidate];
            std::vector<GroupElement> next(next_count,
                                           GroupElement(0, Bout));
            for (int pair_index = 0; pair_index < pair_count; ++pair_index) {
                const int flat = candidate * pair_count + pair_index;
                const int triple = triple_offsets[candidate] + pair_index;
                const uint64_t d = opened[flat].value;
                const uint64_t e = opened[products + flat].value;
                const GroupElement product =
                    material.c[triple] + material.b[triple] * d +
                    material.a[triple] * e + GroupElement(d * e, Bout) *
                    static_cast<uint64_t>(party_id - SERVER);
                next[pair_index] = current[candidate][2 * pair_index] +
                                   current[candidate][2 * pair_index + 1] -
                                   product;
            }
            if (width % 2 == 1) next.back() = current[candidate].back();
            triple_offsets[candidate] += pair_count;
            current[candidate].swap(next);
        }
    }

    std::vector<GroupElement> results(candidates, GroupElement(0, Bout));
    for (int candidate = 0; candidate < candidates; ++candidate) {
        if (triple_offsets[candidate] != materials[candidate]->total_nodes) {
            throw std::logic_error(
                "batchedOrOnlineBatch: triple consumption mismatch");
        }
        results[candidate] = current[candidate].front();
    }
    return results;
}

GroupElement batchedOrFull(
    int party_id,
    const GroupElement* input,
    int dim,
    int Bout
) {
    const BatchedORMaterial material =
        batchedOrOffline(party_id, dim, Bout);
    return batchedOrOnline(party_id, input, material);
}

}  // namespace dfss
