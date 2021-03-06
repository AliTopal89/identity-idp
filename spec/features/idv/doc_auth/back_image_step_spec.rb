require 'rails_helper'

shared_examples 'back image step' do |simulate|
  feature 'doc auth back image step' do
    include IdvStepHelper
    include DocAuthHelper

    before do
      allow(Figaro.env).to receive(:acuant_simulator).and_return(simulate)
      enable_doc_auth
      complete_doc_auth_steps_before_back_image_step
      mock_assure_id_ok
    end

    it 'is on the correct page' do
      expect(page).to have_current_path(idv_doc_auth_back_image_step)
      expect(page).to have_content(t('doc_auth.headings.upload_back'))
    end

    it 'proceeds to the next page with valid info' do
      attach_image
      click_idv_continue

      expect(page).to have_current_path(idv_doc_auth_ssn_step)
    end

    it 'proceeds to the next page if the user does not have a phone' do
      complete_doc_auth_steps_before_back_image_step(create(:user, :with_piv_or_cac))
      attach_image
      click_idv_continue

      expect(page).to have_current_path(idv_doc_auth_ssn_step)
    end

    it 'does not proceed to the next page with invalid info' do
      allow_any_instance_of(Idv::Acuant::AssureId).to receive(:post_back_image).
        and_return([false, ''])
      attach_image
      click_idv_continue

      expect(page).to have_current_path(idv_doc_auth_back_image_step) unless simulate
    end

    it 'does not proceed to the next page with result=2' do
      allow_any_instance_of(Idv::Acuant::AssureId).to receive(:results).
        and_return([true, assure_id_results_with_result_2])
      attach_image
      click_idv_continue

      expect(page).to have_current_path(idv_doc_auth_back_image_step) unless simulate
    end
  end
end

feature 'doc auth back image' do
  it_behaves_like 'back image step', 'false'
  it_behaves_like 'back image step', 'true'
end
