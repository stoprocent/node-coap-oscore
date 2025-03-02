#ifndef OSCORE_ERROR_H
#define OSCORE_ERROR_H

#include <stdexcept>
#include <string>
#include <unordered_map>
extern "C" {
#include "oscore.h"
}

class OscoreError : public std::runtime_error {
public:
    explicit OscoreError(err err_code)
        : std::runtime_error("OSCORE Error: " + error_message(err_code)), code(err_code) {}

    err code;

private:
    static std::string error_message(err err_code) {
        static const std::unordered_map<err, std::string> error_map = {
            {not_oscore_pkt, "Not an OSCORE packet"},
            {first_request_after_reboot, "First request after reboot"},
            {echo_validation_failed, "Echo validation failed"},
            {oscore_unknown_hkdf, "OSCORE unknown HKDF"},
            {token_mismatch, "Token mismatch"},
            {oscore_invalid_algorithm_aead, "OSCORE invalid AEAD algorithm"},
            {oscore_invalid_algorithm_hkdf, "OSCORE invalid HKDF algorithm"},
            {oscore_kid_recipient_id_mismatch, "OSCORE KID recipient ID mismatch"},
            {too_many_options, "Too many options"},
            {oscore_valuelen_to_long_error, "OSCORE value length too long"},
            {oscore_inpkt_invalid_tkl, "OSCORE invalid TKL in incoming packet"},
            {oscore_inpkt_invalid_option_delta, "OSCORE invalid option delta in incoming packet"},
            {oscore_inpkt_invalid_optionlen, "OSCORE invalid option length in incoming packet"},
            {oscore_inpkt_invalid_piv, "OSCORE invalid PIV in incoming packet"},
            {not_valid_input_packet, "Not a valid input packet"},
            {oscore_replay_window_protection_error, "OSCORE replay window protection error"},
            {oscore_replay_notification_protection_error, "OSCORE replay notification protection error"},
            {no_echo_option, "No echo option"},
            {echo_val_mismatch, "Echo validation mismatch"},
            {oscore_ssn_overflow, "OSCORE SSN overflow"},
            {oscore_max_interactions, "OSCORE max interactions reached"},
            {oscore_interaction_duplicated_token, "OSCORE interaction duplicated token"},
            {oscore_interaction_not_found, "OSCORE interaction not found"},
            {oscore_wrong_uri_path, "OSCORE wrong URI path"},
            {oscore_no_response, "OSCORE no response"},
        };

        auto it = error_map.find(err_code);
        return it != error_map.end() ? it->second : "Unknown OSCORE error";
    }
};

#endif // OSCORE_ERROR_H