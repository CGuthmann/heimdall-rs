#! /bin/bash

#sed -i 's/#include "calcwit.hpp"/#include "calcwit.hpp"\n namespace CIRCUIT_NAME{/g' presentation_attribute.cpp 
#echo '}' >> presentation_attribute.cpp 
#
#sed -i 's/#include "calcwit.hpp"/#include "calcwit.hpp"\n namespace CIRCUIT_NAME{/g' presentation_range.cpp 
#echo '}' >> presentation_range.cpp 
#
#sed -i 's/#include "calcwit.hpp"/#include "calcwit.hpp"\n namespace CIRCUIT_NAME{/g' presentation_polygon.cpp 
#echo '}' >> presentation_polygon.cpp 
#
#sed -i 's/#include "calcwit.hpp"/#include "calcwit.hpp"\n namespace CIRCUIT_NAME{/g' presentation_delegation.cpp 
#echo '}' >> presentation_delegation.cpp 
#
sed -i 's/#include "calcwit.hpp"/#include "calcwit.hpp"\n namespace CIRCUIT_NAME{/g' poseidon_bench.cpp 
echo '}' >> poseidon_bench.cpp 
cd ..
make
make android



#cd package/bin
#cp /home/cguth/Vidar/circuits/heimdall/circom/presentations/attribute/input_attribute.json .
#./presentation_attribute input_attribute.json presentation_attribute.wtns
#
#rm /home/cguth/Vidar/circuits/heimdall/circom/presentations/attribute/presentation_attribute.wtns
#cp presentation_attribute.wtns /home/cguth/Vidar/circuits/heimdall/circom/presentations/attribute
#
#cd /home/cguth/Vidar/circuits/heimdall/circom/presentations/attribute
#snarkjs groth16 prove presentation_attribute.zkey presentation_attribute.wtns proof.json public.json
#snarkjs groth16 verify presentation_attribute_vkey.json public.json proof.json
##
##
#cd /home/cguth/lib/witnesscalc/src

#cd ..
#cd package/bin
#cp /home/cguth/Vidar/circuits/heimdall/circom/presentations/range/input_range.json .
#./presentation_range input_range.json presentation_range.wtns
#
#rm /home/cguth/Vidar/circuits/heimdall/circom/presentations/range/presentation_range.wtns
#cp presentation_range.wtns /home/cguth/Vidar/circuits/heimdall/circom/presentations/range
#
#cd /home/cguth/Vidar/circuits/heimdall/circom/presentations/range
#snarkjs groth16 prove presentation_range.zkey presentation_range.wtns proof.json public.json
#snarkjs groth16 verify presentation_range_vkey.json public.json proof.json
##
##
#cd /home/cguth/lib/witnesscalc/src
#
#cd ..
#cd package/bin
#rm test.json
#cp /home/cguth/Vidar/circuits/heimdall/circom/presentations/polygon/input_polygon.json .
#./presentation_polygon input_polygon.json presentation_polygon.wtns
#
#rm /home/cguth/Vidar/circuits/heimdall/circom/presentations/polygon/presentation_polygon.wtns
#cp presentation_polygon.wtns /home/cguth/Vidar/circuits/heimdall/circom/presentations/polygon
#
#cd /home/cguth/Vidar/circuits/heimdall/circom/presentations/polygon
#snarkjs groth16 prove presentation_polygon.zkey presentation_polygon.wtns proof.json public.json
#snarkjs groth16 verify presentation_polygon_vkey.json public.json proof.json
##
##
#cd /home/cguth/lib/witnesscalc/src
#
#cd ..
#cd package/bin
#rm test.json
#cp /home/cguth/Vidar/circuits/heimdall/circom/presentations/delegation/input_delegation.json .
#./presentation_delegation input_delegation.json presentation_delegation.wtns
#
#rm /home/cguth/Vidar/circuits/heimdall/circom/presentations/delegation/presentation_delegation.wtns
#cp presentation_delegation.wtns /home/cguth/Vidar/circuits/heimdall/circom/presentations/delegation

#cd /home/cguth/Vidar/circuits/heimdall/circom/presentations/delegation
#snarkjs groth16 prove presentation_delegation.zkey presentation_delegation.wtns proof.json public.json
#snarkjs groth16 verify presentation_delegation_vkey.json public.json proof.json


cp /home/cguth/lib/witnesscalc/package/lib/* /home/cguth/Vidar/backend/ark-circom-service/lib/x86_64-unknown-linux-gnu
cp /home/cguth/lib/witnesscalc/package/lib/* /home/cguth/Vidar/backend/heimdall/lib/x86_64-unknown-linux-gnu

cp /home/cguth/lib/witnesscalc/package_android/lib/* /home/cguth/Vidar/backend/ark-circom-service/lib/aarch64-linux-android
cp /home/cguth/lib/witnesscalc/package_android/lib/* /home/cguth/Vidar/backend/heimdall/lib/aarch64-linux-android