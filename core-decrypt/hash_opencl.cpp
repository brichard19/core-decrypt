
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <algorithm>
#include <CL/cl.h>

#include "cl_util.h"
#include "util.h"

#include "core-decrypt.h"

// Defined in core-decrypt_cl.cpp
extern char _core_decrypt_cl[];

std::string _kernelSource;

const std::string _alphabet = "abcdefghijklmnopqrstuvwxyz";
unsigned int _alphabet_size = (unsigned int)_alphabet.length();

std::string format(const char *formatStr, double value)
{
    char buf[100] = { 0 };

    sprintf(buf, formatStr, value);

    return std::string(buf);
}

void text_to_file(std::string file_name, std::string text)
{
    std::ofstream f;
    f.open(file_name);
    f << text;
    f.close();
}

std::string formatSeconds(unsigned int seconds)
{
    char s[128] = { 0 };

    unsigned int days = seconds / 86400;
    unsigned int hours = (seconds % 86400) / 3600;
    unsigned int minutes = (seconds % 3600) / 60;
    unsigned int sec = seconds % 60;

    if(days > 0) {
        sprintf(s, "%d:%02d:%02d:%02d", days, hours, minutes, sec);
    }
    else {
        sprintf(s, "%02d:%02d:%02d", hours, minutes, sec);
    }


    return std::string(s);
}

void clCall(cl_int err)
{
    if(err != CL_SUCCESS) {
        std::cout << "OpenCL error: " << getErrorString(err) << std::endl;
        exit(1);
    }
}

void load_kernel_source()
{
    _kernelSource = std::string(_core_decrypt_cl);
}

std::vector<struct device_info> get_devices()
{
    int err = 0;

    unsigned int num_platforms = 0;

    cl_platform_id platform_ids[10];

    std::vector<struct device_info> devices;

    err = clGetPlatformIDs(0, NULL, &num_platforms);

    if(num_platforms == 0) {
        return devices;
    }

    clGetPlatformIDs(num_platforms, platform_ids, NULL);

    // Get device ID's and names
    for(unsigned int i = 0; i < num_platforms; i++) {
        unsigned int num_devices = 0;
        cl_device_id ids[10];

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, 0, NULL, &num_devices);

        if(num_devices == 0) {
            continue;
        }

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, num_devices, ids, NULL);

        for(unsigned int j = 0; j < num_devices; j++) {
            struct device_info d;

            d.logical_id = (int)devices.size();
            d.id = ids[j];

            // Get device name
            char buf[256] = { 0 };
            size_t name_size;
            clGetDeviceInfo(ids[j], CL_DEVICE_NAME, sizeof(buf), buf, &name_size);
            d.name = std::string(buf, name_size);

            unsigned int cores = 0;
            clGetDeviceInfo(ids[j], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cores), &cores, NULL);
            d.cores = cores;

            unsigned int frequency = 0;
            clGetDeviceInfo(ids[j], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(frequency), &frequency, NULL);
            d.clock_frequency = frequency;

            uint64_t memory = 0;
            clGetDeviceInfo(ids[j], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(memory), &memory, NULL);
            d.memory = memory;

            devices.push_back(d);
        }
    }

    return devices;
}

cl_device_id get_device(int idx)
{
    int err = 0;

    unsigned int num_platforms = 0;

    cl_platform_id platform_ids[10];
    std::vector<cl_device_id> device_ids;
    std::vector<std::string> device_names;

    err = clGetPlatformIDs(0, NULL, &num_platforms);

    if(num_platforms == 0) {
        std::cout << "No OpenCL platforms found" << std::endl;
        return 0;
    }

    clGetPlatformIDs(num_platforms, platform_ids, NULL);

    // Get device ID's and names
    for(unsigned int i = 0; i < num_platforms; i++) {
        unsigned int num_devices = 0;
        cl_device_id ids[10];

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, 0, NULL, &num_devices);

        if(num_devices == 0) {
            continue;
        }

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, num_devices, ids, NULL);

        for(unsigned int j = 0; j < num_devices; j++) {
            char buf[256] = { 0 };
            size_t name_size;

            clGetDeviceInfo(ids[j], CL_DEVICE_NAME, sizeof(buf), buf, &name_size);
            device_ids.push_back(ids[j]);
            device_names.push_back(std::string(buf));
        }
    }

    std::cout << "Selected " << device_names[idx] << std::endl;

    return device_ids[idx];
}


void initialize_device_dictionaries(cl_context ctx, cl_command_queue cmd, cl_mem *dev_words, cl_mem *dev_index, cl_mem *dev_offsets, int *password_len, PasswordDictionary &dictionary)
{
    int err;

    std::string& words = dictionary.get_words();
    std::vector<unsigned int>& index = dictionary.get_index();
    std::vector<struct password_offset> offsets = dictionary.get_offsets();


    *dev_words = clCreateBuffer(ctx, 0, words.length(), NULL, &err);
    clCall(err);
    *dev_index = clCreateBuffer(ctx, 0, index.size() * sizeof(unsigned int), NULL, &err);
    clCall(err);
    *dev_offsets = clCreateBuffer(ctx, 0, offsets.size() * sizeof(struct password_offset), NULL, &err);
    clCall(err);
    *password_len = (int)offsets.size();

    // Copy to device
    clCall(clEnqueueWriteBuffer(cmd, *dev_words, CL_TRUE, 0, words.length(), words.c_str(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, *dev_index, CL_TRUE, 0, index.size() * sizeof(unsigned int), index.data(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, *dev_offsets, CL_TRUE, 0, offsets.size() * sizeof(struct password_offset), offsets.data(), 0, NULL, NULL));
}


static void do_dictionary(struct device_info &device, PasswordDictionary &dictionary, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, int stride, unsigned int intensity)
{
    cl_mem dev_index = 0;
    cl_mem dev_words = 0;
    cl_mem dev_offsets = 0;
    cl_mem dev_hashes;
    cl_mem dev_encrypted_block;
    cl_mem dev_iv;
    cl_mem dev_salt;
    cl_mem dev_result;

    int num_words = 0;
    cl_context ctx;
    cl_command_queue cmd;
    cl_program prog;
    cl_kernel start_kernel;
    cl_kernel middle_kernel;
    cl_kernel end_kernel;
    cl_int err = 0;

    uint64_t dictionary_size = dictionary.get_size();

    ctx = clCreateContext(0, 1, &device.id, NULL, NULL, &err);
    clCall(err);

    cmd = clCreateCommandQueue(ctx, device.id, 0, &err);
    clCall(err);

    size_t len = _kernelSource.length();
    const char *ptr = _kernelSource.c_str();
    prog = clCreateProgramWithSource(ctx, 1, &ptr, &len, &err);
    clCall(err);

    std::cout << "Building kernel... ";
    err = clBuildProgram(prog, 0, NULL, NULL, NULL, NULL);
    if(err != CL_SUCCESS)
    {
        char *buffer = NULL;
        size_t len = 0;

        std::cout << "Error: Failed to build program executable! error code " << err << std::endl;
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        buffer = new char[len];
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, len, buffer, NULL);
        std::cout << buffer << std::endl;
        delete[] buffer;
        clCall(err);
    }

    std::cout << "Done" << std::endl;

    start_kernel = clCreateKernel(prog, "dictionary_attack", &err);
    clCall(err);
    middle_kernel = clCreateKernel(prog, "hash_middle", &err);
    clCall(err);
    end_kernel = clCreateKernel(prog, "hash_end", &err);
    clCall(err);


    size_t global = device.cores * 1024;
    size_t local = 64;


    initialize_device_dictionaries(ctx, cmd, &dev_words, &dev_index, &dev_offsets, &num_words, dictionary);

    dev_encrypted_block = clCreateBuffer(ctx, 0, sizeof(unsigned int) * 4, NULL, &err);
    clCall(err);
    dev_iv = clCreateBuffer(ctx, 0, sizeof(unsigned int) * 4, NULL, &err);
    clCall(err);
    dev_salt = clCreateBuffer(ctx, 0, 8, NULL, &err);
    clCall(err);
    dev_hashes = clCreateBuffer(ctx, 0, sizeof(uint64_t) * 8 * global, NULL, &err);
    clCall(err);
    dev_result = clCreateBuffer(ctx, 0, sizeof(int), NULL, &err);
    clCall(err);

    int result = -1;

    // Copy required data over to device
    clCall(clEnqueueWriteBuffer(cmd, dev_encrypted_block, CL_TRUE, 0, sizeof(unsigned int) * 4, encrypted_block, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_iv, CL_TRUE, 0, sizeof(unsigned int) * 4, iv, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_salt, CL_TRUE, 0, 8, salt, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result, 0, NULL, NULL));

    unsigned int start_iterations = 1;
    unsigned int middle_iterations = std::min(intensity, iterations);
    unsigned int middle_kernel_calls = (iterations - 1) / middle_iterations;
    unsigned int end_iterations = iterations - 1 - middle_kernel_calls * middle_iterations;

    uint64_t t0 = getSystemTime();
    uint64_t total_time = 0;

    uint64_t total_passwords = dictionary.get_size();
    int kernel_calls = 0;

    std::cout << "Running..." << std::endl;

    for(uint64_t i = start; i < dictionary_size; i += global * stride) {

        // Set up the next password
        clCall(clSetKernelArg(start_kernel, 0, sizeof(cl_mem), &dev_words));
        clCall(clSetKernelArg(start_kernel, 1, sizeof(cl_mem), &dev_index));
        clCall(clSetKernelArg(start_kernel, 2, sizeof(cl_mem), &dev_offsets));
        clCall(clSetKernelArg(start_kernel, 3, sizeof(unsigned int), &num_words));
        clCall(clSetKernelArg(start_kernel, 4, sizeof(uint64_t), &total_passwords));
        clCall(clSetKernelArg(start_kernel, 5, sizeof(unsigned int), &start_iterations));
        clCall(clSetKernelArg(start_kernel, 6, sizeof(cl_mem), &dev_salt));
        clCall(clSetKernelArg(start_kernel, 7, sizeof(uint64_t), &start));
        clCall(clSetKernelArg(start_kernel, 8, sizeof(int), &stride));
        clCall(clSetKernelArg(start_kernel, 9, sizeof(cl_mem), &dev_hashes));
        clCall(clEnqueueNDRangeKernel(cmd, start_kernel, 1, NULL, &global, &local, 0, NULL, NULL));

        clCall(clFinish(cmd));

        // Do hashing
        for(unsigned int j = 0; j < middle_kernel_calls; j++) {
            clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
            clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &middle_iterations));
            clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &global, &local, 0, NULL, NULL));
            clCall(clFinish(cmd));
        }

        // Check the final hash
        clCall(clSetKernelArg(end_kernel, 0, sizeof(cl_mem), &dev_encrypted_block));
        clCall(clSetKernelArg(end_kernel, 1, sizeof(cl_mem), &dev_iv));
        clCall(clSetKernelArg(end_kernel, 2, sizeof(cl_mem), &dev_hashes));
        clCall(clSetKernelArg(end_kernel, 3, sizeof(unsigned int), &end_iterations));
        clCall(clSetKernelArg(end_kernel, 4, sizeof(cl_mem), &dev_result));
        clCall(clEnqueueNDRangeKernel(cmd, end_kernel, 1, NULL, &global, &local, 0, NULL, NULL));
        clCall(clEnqueueReadBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result, 0, NULL, NULL));
        clCall(clFinish(cmd));
        kernel_calls++;

        if(result >= 0) {
            std::cout << "======== Password found ========" << std::endl;
            uint64_t num = i + result * stride;
            std::string password = dictionary.get_password(num);
            std::cout << "Password: " << password << std::endl;
            std::cout << "================================" << std::endl;

            // Write to file for safe keeping
            std::string file_name = "password_" + std::to_string(t0) + ".txt";
            text_to_file(file_name, password);
            std::cout << "Password written to " << file_name << std::endl;

            break;
        }

        uint64_t t1 = getSystemTime() - t0;
        total_time += t1;

        if(t1 >= 1800) {
            std::cout << device.name.substr(0, 16) << "| "
                << formatSeconds((unsigned int)(total_time/1000)) << " "
                << ((kernel_calls * global) / (t1/1000)) << "/sec "
                << (i + global) << "/" << total_passwords
                << " (" << format("%.3f", std::min(  ((double)(i + global)/total_passwords) * 100.0, 100.0)) << "%)"
                << std::endl;

            t0 = getSystemTime();
            kernel_calls = 0;
        }

        // Update position in password space
        start += global * stride;
    }

    clReleaseMemObject(dev_words);
    clReleaseMemObject(dev_offsets);
    clReleaseMemObject(dev_index);
    clReleaseMemObject(dev_encrypted_block);
    clReleaseMemObject(dev_iv);
    clReleaseMemObject(dev_salt);
    clReleaseMemObject(dev_hashes);
    clReleaseMemObject(dev_result);
}

static void do_brute_force(cl_device_id device_id, int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end)
{
    cl_mem dev_alphabet;
    cl_mem dev_hashes;
    cl_mem dev_encrypted_block;
    cl_mem dev_iv;
    cl_mem dev_salt;
    cl_mem dev_result;
 
    cl_context ctx;
    cl_command_queue cmd;
    cl_program prog;
    cl_kernel start_kernel;
    cl_kernel middle_kernel;
    cl_kernel end_kernel;
    cl_int err = 0;

    ctx = clCreateContext(0, 1, &device_id, NULL, NULL, &err);
    clCall(err);


    cmd = clCreateCommandQueue(ctx, device_id, 0, &err);
    clCall(err);

    size_t len = _kernelSource.length();
    const char *ptr = _kernelSource.c_str();
    prog = clCreateProgramWithSource(ctx, 1, &ptr, &len, &err);
    clCall(err);

    err = clBuildProgram(prog, 0, NULL, NULL, NULL, NULL);
    if(err != CL_SUCCESS)
    {
        char *buffer = NULL;
        size_t len = 0;

        std::cout << "Error: Failed to build program executable! error code " << err << std::endl;
        clGetProgramBuildInfo(prog, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        buffer = new char[len];
        clGetProgramBuildInfo(prog, device_id, CL_PROGRAM_BUILD_LOG, len, buffer, NULL);
        std::cout << buffer << std::endl;
        delete[] buffer;
        clCall(err);
    }

    start_kernel = clCreateKernel(prog, "brute_force_alphabet", &err);
    clCall(err);
    middle_kernel = clCreateKernel(prog, "hash_middle", &err);
    clCall(err);
    end_kernel = clCreateKernel(prog, "hash_end", &err);
    clCall(err);


    size_t global = 2048;
    size_t local = 32;

    dev_alphabet = clCreateBuffer(ctx, 0, _alphabet_size, NULL, &err);
    clCall(err);
    dev_encrypted_block = clCreateBuffer(ctx, 0, sizeof(unsigned int) * 4, NULL, &err);
    clCall(err);
    dev_iv = clCreateBuffer(ctx, 0, sizeof(unsigned int) * 4, NULL, &err);
    clCall(err);
    dev_salt = clCreateBuffer(ctx, 0, 8, NULL, &err);
    clCall(err);
    dev_hashes = clCreateBuffer(ctx, 0, sizeof(uint64_t) * 8 * global, NULL, &err);
    clCall(err);
    dev_result = clCreateBuffer(ctx, 0, sizeof(int), NULL, &err);
    clCall(err);

    int result = -1;

    // Copy required data over to device
    clCall(clEnqueueWriteBuffer(cmd, dev_alphabet, CL_TRUE, 0, _alphabet_size, _alphabet.c_str(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_encrypted_block, CL_TRUE, 0, sizeof(unsigned int) * 4, encrypted_block, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_iv, CL_TRUE, 0, sizeof(unsigned int) * 4, iv, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_salt, CL_TRUE, 0, 8, salt, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result, 0, NULL, NULL));

    unsigned int start_iterations = 1;
    unsigned int middle_iterations = 1000;
    unsigned int middle_kernel_calls = (iterations - 1) / 1000;
    unsigned int end_iterations = iterations - 1 - middle_kernel_calls * 1000;

    uint64_t t0 = getSystemTime();

    clCall(clSetKernelArg(start_kernel, 0, sizeof(cl_mem), &dev_alphabet));
    clCall(clSetKernelArg(start_kernel, 1, sizeof(unsigned int), &_alphabet_size));
    clCall(clSetKernelArg(start_kernel, 2, sizeof(unsigned int), &password_len));
    clCall(clSetKernelArg(start_kernel, 3, sizeof(unsigned int), &start_iterations));
    clCall(clSetKernelArg(start_kernel, 4, sizeof(cl_mem), &dev_salt));
    clCall(clSetKernelArg(start_kernel, 5, sizeof(uint64_t), &start));
    clCall(clSetKernelArg(start_kernel, 6, sizeof(cl_mem), &dev_hashes));
    clCall(clEnqueueNDRangeKernel(cmd, start_kernel, 1, NULL, &global, &local, 0, NULL, NULL));

    clCall(clFinish(cmd));

    for(unsigned int j = 0; j < middle_kernel_calls; j++) {
        clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
        clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &middle_iterations));
        clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &global, &local, 0, NULL, NULL));
        clCall(clFinish(cmd));
    }

    clCall(clSetKernelArg(end_kernel, 0, sizeof(cl_mem), &dev_encrypted_block));
    clCall(clSetKernelArg(end_kernel, 1, sizeof(cl_mem), &dev_iv));
    clCall(clSetKernelArg(end_kernel, 2, sizeof(cl_mem), &dev_hashes));
    clCall(clSetKernelArg(end_kernel, 3, sizeof(unsigned int), &end_iterations));
    clCall(clSetKernelArg(end_kernel, 4, sizeof(cl_mem), &dev_result));
    clCall(clEnqueueNDRangeKernel(cmd, end_kernel, 1, NULL, &global, &local, 0, NULL, NULL));

    clCall(clEnqueueReadBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result, 0, NULL, NULL));
    
    clCall(clFinish(cmd));


    if(result >= 0) {
        std::cout << "Password found!" << std::endl;
    }

    uint64_t t1 = getSystemTime() - t0;
    std::cout << global << " keys in " << (t1 / 1000) << " seconds" << std::endl;

    clReleaseMemObject(dev_alphabet);
    clReleaseMemObject(dev_encrypted_block);
    clReleaseMemObject(dev_iv);
    clReleaseMemObject(dev_salt);
    clReleaseMemObject(dev_hashes);
    clReleaseMemObject(dev_result);
}

bool brute_force_cl(int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end, uint64_t stride)
{
    cl_device_id device = get_device(0);
    load_kernel_source();
    do_brute_force(device, password_len, encrypted_block, iv, salt, iterations, start, end);

    return true;
}

bool dictionary_cl(struct device_info &device, PasswordDictionary &dictionary, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, int stride, unsigned int intensity)
{
    load_kernel_source();

    do_dictionary(device, dictionary, encrypted_block, iv, salt, iterations, start, stride, intensity);

    return true;
}